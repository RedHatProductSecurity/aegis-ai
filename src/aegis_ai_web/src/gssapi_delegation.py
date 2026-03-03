"""
GSSAPI middleware that requests credential delegation and stores the security
context in the request scope so OSIDB can use the client's Kerberos identity
"""

import base64
import logging
from typing import Union

from gssapi.creds import Credentials
from gssapi.names import Name
from gssapi.sec_contexts import SecurityContext
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)


class GSSAPIDelegationMiddleware:
    """
    ASGI middleware that authenticates the client with Kerberos/GSSAPI and
    requests credential delegation. When the client delegates (e.g. kinit -f),
    the security context is stored in scope["gssapi_context"] so downstream
    code can use delegated_creds for OSIDB (pass-through authentication).
    """

    def __init__(self, app: ASGIApp, *, spn: Union[str, Name, None] = None) -> None:
        if isinstance(spn, str):
            spn = Name(spn)
        self.app = app
        self.creds = Credentials(usage="accept", name=spn)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        auth = headers.get("Authorization", "")
        if not auth or not auth.startswith("Negotiate "):
            resp = Response(
                status_code=401,
                headers=Headers({"WWW-Authenticate": "Negotiate"}),
            )
            await resp(scope, receive, send)
            return

        try:
            token = base64.b64decode(auth.split(" ")[1])
        except Exception as e:
            logger.debug("GSSAPI: invalid Authorization header: %s", e)
            resp = Response(
                status_code=401,
                headers=Headers({"WWW-Authenticate": "Negotiate"}),
            )
            await resp(scope, receive, send)
            return

        # Accept the client's security context. Delegation is controlled by the
        # client (e.g. curl --negotiate with kinit -f); when the client
        # delegates, ctx.delegated_creds will be set for OSIDB pass-through.
        ctx = SecurityContext(creds=self.creds)
        gssresp = ctx.step(token)

        if ctx.complete:
            username = str(ctx.initiator_name)
            if username:
                scope["username"] = username
            # Store context so OSIDB client can use delegated_creds when present
            scope["gssapi_context"] = ctx

            async def send_gss(message: Message) -> None:
                if message["type"] == "http.response.start" and gssresp:
                    message.setdefault("headers", [])
                    headers_mut = MutableHeaders(scope=message)
                    headers_mut["WWW-Authenticate"] = "Negotiate " + base64.b64encode(
                        gssresp
                    ).decode("utf-8")
                await send(message)

            await self.app(scope, receive, send_gss)
        else:
            if gssresp:
                negotiate_header = "Negotiate " + base64.b64encode(gssresp).decode(
                    "utf-8"
                )
            else:
                negotiate_header = "Negotiate"
            resp = Response(
                status_code=401,
                headers=Headers({"WWW-Authenticate": negotiate_header}),
            )
            await resp(scope, receive, send)
