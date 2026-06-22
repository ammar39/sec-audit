# Dashboard

`sec_audit.dashboard` is not yet shipped. The module described below is
**planned** — it does not exist in any current distribution.

## Scope

The dashboard is optional and must support shared data services consumed by both
standalone ASGI routes and Django views.

## Services

`sec_audit.dashboard.services` owns source querying, alert mapping, severity
labels, filtering/search, pagination, and stats aggregation.

It must have zero framework imports:

- no Django imports
- no Starlette imports
- no request/response/template/routing imports

## Standalone ASGI App

`sec_audit.dashboard.app` exposes `make_app(log_path=None, source=None)`.

Starlette imports must be guarded. If Starlette is unavailable, raise exactly:

```python
ImportError('Install sec_audit[dashboard] to use the standalone ASGI dashboard.')
```

## Django Views

Django views and URLs may import Django, but they should delegate source querying,
alert mapping, and stats work to `dashboard.services`.

## UI Pattern

Keep the dashboard server-rendered with lightweight partial updates. Do not add a
React/Vue build pipeline.
