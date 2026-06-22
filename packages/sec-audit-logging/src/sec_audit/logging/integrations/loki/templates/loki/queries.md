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
