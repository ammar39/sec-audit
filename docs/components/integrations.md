# Integrations

The package ships integration assets in two distributions:

**`sec-audit-logging`** — Grafana Alloy, Loki, Grafana dashboard templates, and
LogQL examples. It does not implement a Python Loki client and does not claim
OTLP export.

**`sec-audit-rules`** — Wazuh XML rules and Sigma YAML rules for SIEM
correlation. See `sec_audit.integrations.wazuh`.

Primary path:

```text
Django -> stdout JSONL -> Grafana Alloy -> Loki -> Grafana
```

Secondary path:

```text
Django -> JSONL file -> Grafana Alloy -> Loki -> Grafana
```

Use only low-cardinality Loki labels:

- `service_name`
- `environment`
- `severity`
- `event_type`

Keep request IDs, user IDs, session IDs, IP addresses, paths, routes, and object
IDs inside the JSON body.
