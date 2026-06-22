"""Pytest collection hooks for the sec-audit workspace.

The logging release (``sec-audit``, ``sec-audit-logging``, ``django-sec-audit``)
is validated on its own, without ``sec-audit-rules`` installed (see the README
development command). When ``sec-audit-rules`` is absent we skip collection of
the rules package tests and the cross-distribution boundary tests, which require
all four distributions to be installed together. With all four installed the
ignore list is empty and the full suite runs.
"""

import importlib.util

# The enforcement distribution's tests are Django-ORM-backed and need their own
# settings module + pytest-django, so they run as their own job from the package
# directory (cd packages/django-sec-audit-enforcement). They are excluded from
# the workspace-wide collection, which has no DJANGO_SETTINGS_MODULE configured.
collect_ignore: list[str] = ['packages/django-sec-audit-enforcement/tests']
if importlib.util.find_spec('sec_audit.rules') is None:
    collect_ignore += [
        'packages/sec-audit-rules/tests/test_context_rules.py',
        'packages/sec-audit-rules/tests/test_enforcement.py',
        'packages/sec-audit-rules/tests/test_redis_stores.py',
        'packages/sec-audit-rules/tests/test_rules.py',
        'packages/sec-audit-rules/tests/test_scope_registry.py',
        'packages/sec-audit-rules/tests/test_wazuh_assets.py',
        'tests/test_state.py',
        'tests/test_import_boundaries.py',
        'tests/test_packaging_boundaries.py',
    ]
