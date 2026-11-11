"""SDK-shaped single-page selection adapter for legacy orchestration doubles."""

from types import SimpleNamespace


class Clock:
    def __init__(self):
        self.now = 10_000.0

    def monotonic(self):
        return self.now

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class RecordingClient:
    """Stable SDK client: retiming never grows a mock parent hierarchy."""

    def __init__(self):
        self.timeouts = []
        self.timeout = None

    def with_timeout(self, timeout):
        self.timeout = timeout
        self.timeouts.append(timeout)
        return self


def add_list_page(session):
    """Both real SDK sessions expose retrieve_list and retrieve_list_iterator.

    Reuse the double's filtering behavior, preserving its recorded queries,
    while exposing the mapping/list-page contract of retrieve_list().to_dict().
    """

    iterator = session.flaws.retrieve_list_iterator.side_effect
    session._Session__client = RecordingClient()
    session.call.side_effect = lambda endpoint, *args, **kwargs: endpoint(
        *args, client=session._Session__client, **kwargs
    )

    def retrieve_iterator(**params):
        def fetch(*, client, **query):
            return list(iterator(**query))

        return iter(session.call(fetch, **params))

    session.flaws.retrieve_list_iterator.side_effect = retrieve_iterator

    def retrieve_list(**params):
        rows = [row.to_dict() for row in session.flaws.retrieve_list_iterator(**params)]
        offset, limit = params.get("offset", 0), params.get("limit", 1000)
        payload = {
            "results": rows[offset : offset + limit],
            "count": len(rows),
            "next": "next" if offset + limit < len(rows) else None,
            "previous": None,
        }
        return SimpleNamespace(to_dict=lambda: payload)

    session.flaws.retrieve_list.side_effect = retrieve_list
    return session
