# Aegis built in CLI

A minimal cli (based on click) mainly for testing purposes

```commandline
uv run aegis suggest-impact "CVE-2024-12345"
```

To switch main agent to use with CLI set the AEGIS_CLI_FEATURE_AGENT.

To use public agent (which is default setting):
```commandline
export AEGIS_CLI_FEATURE_AGENT="public"
```
To use Redhat agent:
```commandline
export AEGIS_CLI_FEATURE_AGENT="redhat"
```
