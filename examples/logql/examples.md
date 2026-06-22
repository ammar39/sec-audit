# LogQL Examples

These queries assume Alloy labels only `service_name`, `environment`,
`severity`, and `event_type`.

```logql
sum(count_over_time({service_name="django-sec-audit"}[$__range]))
```

```logql
sum by (event_type) (
  count_over_time({service_name="django-sec-audit"}[$__interval])
)
```

```logql
sum(count_over_time({
  service_name="django-sec-audit",
  event_type=~"auth.login.failed|auth.logout.failed|http.response.client_error|http.response.server_error"
}[$__range]))
```

```logql
sum by (status_code) (
  count_over_time({
    service_name="django-sec-audit"
  } | json status_code="attributes['http.response.status_code']" | status_code!="" [$__interval])
)
```

```logql
{service_name="django-sec-audit", event_type=~"model.create|model.update|model.delete"}
```
