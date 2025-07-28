# OpenTelemetry (OTEL)

[OpenTelemetry](https://opentelemetry.io/) (OTEL) is an observability framework for collecting, generating,
and exporting telemetry data (traces, metrics, and logs, aka [signals](https://opentelemetry.io/docs/concepts/signals/))
to improve system monitoring and performance. 

It is a [CNCF project](https://www.cncf.io/projects/opentelemetry/), ensuring vendor-neutral and standardized observability solutions for cloud-native applications.

## Use logfire to capture OTEL traces

We use [logfire](https://ai.pydantic.dev/logfire) ... as it integrates nicely with pydantic-ai - though can be used without the commerical
cloud product. We can send OTEL traces to anything that supports it (ex. grafana, promethues, etc).

https://ai.pydantic.dev/logfire/#logfire-with-an-alternative-otel-backend

## To enable OTEL

First set where we send OTEL traces to:
```commandline
export OTEL_EXPORTER_OTLP_ENDPOINT='http://localhost:4318'
```
Then enable
```commandline
export AEGIS_OTEL_ENABLED="true"
```
To run a standalone OTEL viewer:
```commandline
make run-otel
```


