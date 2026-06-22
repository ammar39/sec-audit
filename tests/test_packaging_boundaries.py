"""Combined packaging/import boundaries for the four-distribution split.

Asserts the composition contract that holds in the dev/CI environment where
all four distributions are installed together:

1. sec-audit            -> only sec_audit.core
2. sec-audit-logging    -> imports without Django
3. sec-audit-rules      -> imports without Django
4. django-sec-audit         -> composes core + logging + Django

The framework-free assertions run in subprocesses so ``sys.modules`` reflects
only that distribution's own transitive imports, not modules loaded by other
tests.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(code, **kw):
    return subprocess.run(
        [sys.executable, '-c', code],
        capture_output=True,
        text=True,
        check=True,
        **kw,
    )


# (1) Each distribution ships only its own subpackages. In the combined dev
# venv all four editable installs share the namespace, so we verify against
# each package's source tree directly (the build-time `only-include` is the
# real ownership contract).
@pytest.mark.parametrize(
    ('package', 'shipped'),
    [
        ('sec-audit', {'core'}),
        ('sec-audit-logging', {'logging'}),
        ('sec-audit-rules', {'rules', 'enforcement', 'integrations'}),
        ('django-sec-audit', {'django'}),
    ],
)
def test_each_distribution_owns_only_its_subpackages(package, shipped):
    src = REPO_ROOT / 'packages' / package / 'src' / 'sec_audit'
    found = {p.name for p in src.iterdir() if p.is_dir()} - {'__pycache__'}
    assert found == shipped, f'{package} source owns {found}, expected {shipped}'


# (2)+(3) logging, rules, enforcement are framework-free
@pytest.mark.parametrize(
    'pkg',
    ['sec_audit.logging', 'sec_audit.rules', 'sec_audit.enforcement'],
)
def test_framework_free_packages_do_not_import_django(pkg):
    code = (
        f'import importlib, sys\n'
        f'importlib.import_module("{pkg}")\n'
        f'print("HAS_DJANGO=" + str("django" in sys.modules))\n'
    )
    out = _run(code).stdout
    assert 'HAS_DJANGO=True' not in out, f'{pkg} imports django'


# (4) django-sec-audit composes core + logging + Django. Force the settings
# module (do not setdefault) so a parent project's env var can't leak in.
def test_dj_sec_audit_composes_logging_layers_only():
    code = (
        'import os, sys\n'
        'os.environ["DJANGO_SETTINGS_MODULE"] = "demo.settings"\n'
        'sys.path.insert(0, "demo")\n'
        'import django\n'
        'django.setup()\n'
        'from sec_audit.django.middleware import AuditMiddleware\n'
        'from sec_audit.core import CoreAuditConfig\n'
        'from sec_audit.logging import emit_event\n'
        'print("OK=core,logging,django")\n'
    )
    env = dict(os.environ)
    env.pop('DJANGO_SETTINGS_MODULE', None)
    out = _run(code, cwd=str(REPO_ROOT), env=env).stdout
    assert 'OK=core,logging,django' in out


def test_django_package_source_has_no_rule_enforcement_modules():
    src = REPO_ROOT / 'packages' / 'django-sec-audit' / 'src' / 'sec_audit' / 'django'
    forbidden = {
        'rules',
        'enforcement',
        'blocking',
        'stores',
        'history.py',
        'blocks.py',
    }
    found = {p.name for p in src.iterdir() if p.name in forbidden}
    assert found == set()


def test_django_package_metadata_has_no_rules_dependency():
    pyproject = (
        REPO_ROOT / 'packages' / 'django-sec-audit' / 'pyproject.toml'
    ).read_text()
    assert 'sec-audit-rules' not in pyproject
