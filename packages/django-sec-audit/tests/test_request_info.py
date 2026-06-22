from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.context import (
    AuditContext,
    clear_context,
    get_context,
    reset_context,
    set_context,
)
from sec_audit.django.logging.request_info import build_request_info


def _kwargs(**overrides):
    kwargs = dict(
        method='GET',
        path='/x',
        url='https://example.test/x',
        headers={'X-Request-Id': 'evil'},
        meta={'REMOTE_ADDR': '203.0.113.5'},
        config=CoreAuditConfig(),
    )
    kwargs.update(overrides)
    return kwargs


def test_client_request_id_header_is_ignored():
    clear_context()
    try:
        data = build_request_info(**_kwargs())
    finally:
        clear_context()

    # The client-supplied header must never become the canonical request id.
    assert data['request_id'] != 'evil'
    assert len(data['request_id']) == 32  # generate_id() returns a full UUID4 hex


def test_explicit_internal_request_id_arg_is_honored():
    clear_context()
    try:
        data = build_request_info(**_kwargs(request_id='arg-id'))
    finally:
        clear_context()

    assert data['request_id'] == 'arg-id'


def test_context_request_id_is_honored():
    set_context(
        AuditContext(
            request_id='ctx-id',
            session_id='',
            url='/x',
            path='/x',
            srcip='203.0.113.5',
            method='GET',
        )
    )
    try:
        data = build_request_info(**_kwargs(request_id='arg-id'))
    finally:
        clear_context()

    # Context id wins over both the arg and any client header.
    assert data['request_id'] == 'ctx-id'


def test_nested_context_reset_restores_outer_context():
    clear_context()
    outer = AuditContext(
        request_id='outer',
        session_id='',
        url='/outer',
        path='/outer',
        srcip='203.0.113.5',
        method='GET',
    )
    inner = AuditContext(
        request_id='inner',
        session_id='',
        url='/inner',
        path='/inner',
        srcip='203.0.113.6',
        method='POST',
    )

    outer_token = set_context(outer)
    inner_token = set_context(inner)
    try:
        assert get_context().request_id == 'inner'
        reset_context(inner_token)
        assert get_context().request_id == 'outer'
    finally:
        reset_context(outer_token)
        clear_context()
