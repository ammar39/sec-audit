import importlib
import sys

import pytest


@pytest.mark.parametrize(
    'module_name',
    [
        'sec_audit',
        'sec_audit.core',
        'sec_audit.logging',
        'sec_audit.rules',
        'sec_audit.enforcement',
    ],
)
def test_framework_free_imports_do_not_import_django(module_name):
    prefixes = ('sec_audit', 'django')
    previous = {
        name: module
        for name, module in sys.modules.items()
        if name == 'sec_audit' or name.startswith(prefixes)
    }
    for name in previous:
        sys.modules.pop(name, None)

    try:
        importlib.import_module(module_name)

        assert 'django' not in sys.modules
    finally:
        for name in list(sys.modules):
            if name == 'sec_audit' or name.startswith(prefixes):
                sys.modules.pop(name, None)
        sys.modules.update(previous)


@pytest.mark.parametrize(
    'module_name', ['sec_audit', 'sec_audit.core', 'sec_audit.logging']
)
def test_framework_free_imports_do_not_import_asgiref(module_name):
    # asgiref is Django's async infrastructure. The framework-neutral core and
    # logging packages must not depend on it; the request context uses stdlib
    # contextvars instead.
    prefixes = ('sec_audit', 'asgiref')
    previous = {
        name: module
        for name, module in sys.modules.items()
        if name == 'sec_audit' or name.startswith(prefixes)
    }
    for name in previous:
        sys.modules.pop(name, None)

    try:
        importlib.import_module(module_name)

        assert 'asgiref' not in sys.modules
    finally:
        for name in list(sys.modules):
            if name == 'sec_audit' or name.startswith(prefixes):
                sys.modules.pop(name, None)
        sys.modules.update(previous)
