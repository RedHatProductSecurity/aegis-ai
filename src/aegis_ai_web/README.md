# Aegis web

A minimal web server (based on fastapi) that can be used for integration and testing.

```commandline
make run-web
```
or directly via

```commandline
uv run uvicorn src.aegis_ai_web.src.main:app --port 8000
```
## REST-API

OpenAPI definition is available dynamically:
http://localhost:9000/openapi.json
http://localhost:9000/openapi.yml

REST API documentation is available via
http://localhost:9000/redoc
or
http://localhost:9000/docs


## Developer console

To enable developer console

```commandline
export AEGIS_WEB_ENABLE_CONSOLE=true 
```

## Running endpoint tests

```commandline
make test-web
```