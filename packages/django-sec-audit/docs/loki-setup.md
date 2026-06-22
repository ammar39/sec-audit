# Shipping audit logs to Loki + Grafana

`django-sec-audit` emits one OpenTelemetry LogRecord-shaped JSON object per line. This
guide stands up a local Grafana Alloy → Loki → Grafana stack that collects those lines
and renders a prebuilt security dashboard.

You do **not** hand-write any Alloy/Loki/Grafana config. The `sec-audit-loki-init`
command — shipped by the `sec-audit-logging` dependency you already have — generates the
whole stack from the package's canonical templates.

## Pipeline

```
sec_audit.audit logger ──(OTel JSONL)──▶ Grafana Alloy ──▶ Loki ──▶ Grafana
```

There are two collection paths:

| Path | When | How Alloy reads logs |
|------|------|----------------------|
| **stdout** (recommended for prod) | Containerised app under supervisord/Docker | `loki.source.docker` tails container stdout (`alloy/config.stdout.alloy`) |
| **file-tail** (local / demo default) | Local box, log written to a file | `loki.source.file` tails a JSONL file the generated `docker-compose.yml` mounts |

The generated `docker-compose.yml` is wired for the **file-tail** path out of the box — it's
the fastest way to see data. The stdout path is the production pattern; switching to it is a
small edit covered at the end.

## Step 1 — Emit audit JSONL

### Production: stdout

Use the stdout handler from the [README Quick Start](https://github.com/ammar39/sec-audit/blob/main/packages/django-sec-audit/README.md#quick-start)
(`logging.StreamHandler` + the `audit_jsonl` formatter). Your process supervisor captures
stdout; Alloy collects it from the container.

### Local / demo: write a file Alloy can tail

Point the `audit_jsonl` formatter at a `RotatingFileHandler` so there's a file on disk to mount:

```python
# settings.py
AUDIT_LOG_PATH = 'logs/sec-audit.jsonl'

SEC_AUDIT = {
    'core': {'source': 'myapp'},      # becomes resource.service.name == Loki service_name label
    'logging': {'schema_version': '1.0'},
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'audit_jsonl': {
            '()': 'sec_audit.django.logging.formatters.audit_jsonl_formatter',
        },
    },
    'handlers': {
        'audit_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': AUDIT_LOG_PATH,
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'audit_jsonl',
        },
    },
    'loggers': {
        'sec_audit.audit': {
            'handlers': ['audit_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
```

> The `source` you set here is the value Grafana queries by. Pass the **same** string to
> `--app-label` in the next step so the prefilled dashboard/queries match.

## Step 2 — Generate the monitoring stack

From your project root:

```bash
sec-audit-loki-init monitoring \
  --app-label myapp \
  --environment prod \
  --audit-log-path ../logs/sec-audit.jsonl \
  --dashboard-title "MyApp Security Audit"
```

This writes a self-contained `monitoring/` directory:

```
monitoring/
├── docker-compose.yml                         # loki + alloy + grafana (ports bound to 127.0.0.1)
├── alloy/config.alloy                         # file-tail pipeline (used by docker-compose)
├── alloy/config.stdout.alloy                  # stdout pipeline (production alternative)
├── loki/local-config.yml
├── loki/queries.md                            # LogQL recipes, prefilled with your --app-label
├── grafana/provisioning/datasources/loki.yml
├── grafana/provisioning/dashboards/dashboards.yml
├── grafana/dashboards/sec-audit-overview.json # prebuilt 8-panel dashboard
└── README.md
```

Flags (all optional except `target_dir`):

| Flag | Default | Notes |
|------|---------|-------|
| `--app-label` | `django-sec-audit` | **Must equal** `SEC_AUDIT['core']['source']` |
| `--environment` | `demo` | Static `environment` stream label |
| `--audit-log-path` | `../logs/sec-audit.jsonl` | Host path mounted into the Alloy container (relative to `monitoring/`) |
| `--grafana-admin-user` | `admin` | |
| `--grafana-admin-password` | *generated* | A strong password is generated and printed if omitted — store it; it is not saved elsewhere |
| `--dashboard-title` | `Sec Audit Monitoring` | Grafana dashboard title |
| `--overwrite` | off | Required to regenerate over existing files |

The command prints every file it wrote, the Grafana credentials, and a local-only warning.

## Step 3 — Run it

```bash
mkdir -p logs && touch logs/sec-audit.jsonl     # the file Alloy mounts must exist first
docker compose -f monitoring/docker-compose.yml up -d
```

Then generate some audited traffic in your Django app (hit any route, log in, etc.).

## Step 4 — Verify

Confirm Alloy loaded its config and is tailing the file:

```bash
docker compose -f monitoring/docker-compose.yml logs alloy --tail=30
```

Confirm Loki received events (replace `myapp` with your `--app-label`):

```bash
curl -G http://127.0.0.1:3100/loki/api/v1/query \
  --data-urlencode 'query=count_over_time({service_name="myapp"}[5m])'
```

Open Grafana at `http://localhost:3000`, log in with the printed credentials, and open the
provisioned **MyApp Security Audit** dashboard.

## Labels and LogQL

Alloy projects only four low-cardinality fields to Loki **stream labels**:

| Label | Source |
|-------|--------|
| `service_name` | `resource.service.name` (= `SEC_AUDIT['core']['source']`) |
| `environment` | static, from `--environment` |
| `severity` | top-level `severity_text` |
| `event_type` | `attributes.event_type` |

Everything high-cardinality (`source.address`, `url.path`, `user.id`, `session.id`,
`request_id`, object IDs) stays in the JSON body — query it with the `| json` stage:

```logql
# Events by type
sum by (event_type) (count_over_time({service_name="myapp"}[$__interval]))

# Auth + HTTP failures
sum(count_over_time({service_name="myapp",
  event_type=~"auth.login.failed|http.response.client_error|http.response.server_error"}[$__range]))

# Top source IPs (pulled from the JSON body)
topk(10, sum by (source_address) (count_over_time(
  {service_name="myapp"} | json source_address="attributes['source.address']" | source_address!="" [1h])))
```

The generated `monitoring/loki/queries.md` has the full recipe set, prefilled with your label.

## Production notes

- **Ports bind to `127.0.0.1`.** The stack is local-only by design. Do not publish these
  ports or reuse the generated Grafana credentials in a shared/staging environment.
- **Rotate the Grafana admin password** before any non-local use.
- **Prefer stdout collection in production.** To switch the generated stack from file-tail to
  stdout, point the `alloy` service at `config.stdout.alloy` and give it Docker socket access —
  edit `monitoring/docker-compose.yml`:
  ```yaml
  alloy:
    command: run --server.http.listen-addr=0.0.0.0:12345 --storage.path=/var/lib/alloy/data /etc/alloy/config.stdout.alloy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./alloy/config.stdout.alloy:/etc/alloy/config.stdout.alloy:ro
  ```
  The container-name filter in `config.stdout.alloy` matches `"{{ app-label }}.*"`; adjust it to
  how your Django container is actually named.

## Regenerate after upgrades

When you upgrade `django-sec-audit`/`sec-audit-logging`, refresh the generated assets:

```bash
sec-audit-loki-init monitoring --overwrite \
  --app-label myapp --environment prod --audit-log-path ../logs/sec-audit.jsonl
```

The canonical templates live in the `sec-audit-logging` package
(`sec_audit.logging.integrations.loki.templates`) — they are the source of truth; the
`monitoring/` directory is a generated consumer.
