# Loki Labels and LogQL Query Examples

Grafana Alloy projects only low-cardinality fields from the OpenTelemetry
LogRecord-shaped JSONL body into Loki stream labels. Everything else remains in
the JSON record and should be queried with `| json`.

## Stream Labels

| Label | Source |
|---|---|
| `service_name` | From record body `resource.service.name` (= `SEC_AUDIT['core']['source']`) |
| `environment` | Static deployment label |
| `severity` | Top-level `severity_text` |
| `event_type` | `attributes.event_type` |

Keep request IDs, user IDs, session IDs, source IPs, paths, routes, and object
IDs inside the JSON body.

> The `service_name` label is now taken from the record body, so it always
> matches the emitted record. The query recipes below filter on
> `service_name="{{ APP_LABEL }}"` — run `sec-audit-loki-init` with
> `--app-label` set to your `SEC_AUDIT['core']['source']` so the prefilled
> queries match.

## Query Recipes

### Total Events

```logql
sum(count_over_time({service_name="{{ APP_LABEL }}"}[$__range]))
```

### Events By Type

```logql
sum by (event_type) (
  count_over_time({service_name="{{ APP_LABEL }}"}[$__interval])
)
```

### Failures

```logql
sum(count_over_time({
  service_name="{{ APP_LABEL }}",
  event_type=~"auth.login.failed|auth.logout.failed|http.response.client_error|http.response.server_error"
}[$__range]))
```

### Status Codes

```logql
sum by (status_code) (
  count_over_time({
    service_name="{{ APP_LABEL }}"
  } | json status_code="attributes['http.response.status_code']" | status_code!="" [$__interval])
)
```

### Top Source Addresses

```logql
topk(10,
  sum by (source_address) (
    count_over_time({
      service_name="{{ APP_LABEL }}"
    } | json source_address="attributes['source.address']" | source_address!="" [1h])
  )
)
```

### Model Changes

```logql
{service_name="{{ APP_LABEL }}", event_type=~"model.create|model.update|model.delete"}
```

### Raw Explorer

```logql
{service_name="{{ APP_LABEL }}"}
```

## Enforcement Events

These recipes cover the `audit.enforcement.*` events emitted by
`django-sec-audit-enforcement`. They ride the same logger, formatter, and
JSONL schema as the base events above, so no extra Loki/Alloy configuration is
needed — only `service_name="{{ APP_LABEL }}"`.

### All Enforcement Events

```logql
{service_name="{{ APP_LABEL }}", event_type=~"audit.enforcement.*"}
```

### Requests Blocked

```logql
sum(count_over_time({
  service_name="{{ APP_LABEL }}",
  event_type="audit.enforcement.blocked"
}[$__range]))
```

### Blocks Applied

```logql
sum(count_over_time({
  service_name="{{ APP_LABEL }}",
  event_type="audit.enforcement.block_applied"
}[$__range]))
```

### Blocks By Rule

```logql
topk(10,
  sum by (rule_name) (
    count_over_time({
      service_name="{{ APP_LABEL }}",
      event_type=~"audit.enforcement.blocked|audit.enforcement.block_applied"
    } | json rule_name="attributes['security_rule.name']" | rule_name!="" [$__interval])
  )
)
```

### Blocks By Scope Type

```logql
sum by (scope_type) (
  count_over_time({
    service_name="{{ APP_LABEL }}",
    event_type=~"audit.enforcement.*"
  } | json scope_type="attributes['scope.type']" | scope_type!="" [$__interval])
)
```

### Evaluation Failures By Fail Mode

`audit.enforcement.evaluation_failed` should sit near zero. A spike means the
block store or rule engine errored; `enforcement.fail_mode` shows whether the
request was allowed (`open`) or denied (`closed`).

```logql
sum by (fail_mode) (
  count_over_time({
    service_name="{{ APP_LABEL }}",
    event_type="audit.enforcement.evaluation_failed"
  } | json fail_mode="attributes['enforcement.fail_mode']" | fail_mode!="" [$__interval])
)
```
