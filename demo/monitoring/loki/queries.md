# Loki Labels and LogQL Query Examples

Grafana Alloy projects only low-cardinality fields from the OpenTelemetry
LogRecord-shaped JSONL body into Loki stream labels. Everything else remains in
the JSON record and should be queried with `| json`.

## Stream Labels

| Label | Source |
|---|---|
| `service_name` | Static deployment label |
| `environment` | Static deployment label |
| `severity` | Top-level `severity_text` |
| `event_type` | `attributes.event_type` |

Keep request IDs, user IDs, session IDs, source IPs, paths, routes, and object
IDs inside the JSON body.

## Query Recipes

### Total Events

```logql
sum(count_over_time({service_name="django-sec-audit"}[$__range]))
```

### Events By Type

```logql
sum by (event_type) (
  count_over_time({service_name="django-sec-audit"}[$__interval])
)
```

### Failures

```logql
sum(count_over_time({
  service_name="django-sec-audit",
  event_type=~"auth.login.failed|auth.logout.failed|http.response.client_error|http.response.server_error"
}[$__range]))
```

### Status Codes

```logql
sum by (status_code) (
  count_over_time({
    service_name="django-sec-audit"
  } | json status_code="attributes['http.response.status_code']" | status_code!="" [$__interval])
)
```

### Top Source Addresses

```logql
topk(10,
  sum by (source_address) (
    count_over_time({
      service_name="django-sec-audit"
    } | json source_address="attributes['source.address']" | source_address!="" [1h])
  )
)
```

### Model Changes

```logql
{service_name="django-sec-audit", event_type=~"model.create|model.update|model.delete"}
```

### Raw Explorer

```logql
{service_name="django-sec-audit"}
```
