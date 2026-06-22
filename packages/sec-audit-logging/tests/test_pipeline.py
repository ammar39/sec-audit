"""AuditPipeline + emit_event behavior, including failure isolation semantics."""

import logging

import pytest

from sec_audit.core.events import AuditEvent
from sec_audit.logging import AuditPipeline, LoggingRuntime, emit_event
from sec_audit.logging.pipeline import AuditPipeline as _Pipeline  # noqa: F401


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)

    @property
    def audit_records(self):
        # Only records produced by emit_event (they carry audit_attributes).
        return [r for r in self.records if hasattr(r, 'audit_attributes')]


def _make_logger():
    logger = logging.Logger('tests.audit')
    capture = _Capture()
    logger.addHandler(capture)
    logger.setLevel(logging.DEBUG)
    return logger, capture


class _DropIfMarked:
    def filter(self, event):
        return event.attributes.get('drop') is not True


class _RaiseFilter:
    def filter(self, attributes):
        raise RuntimeError('boom')


class _AddField:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def enrich(self, event):
        return {self.key: self.value}


class _RaiseEnricher:
    def enrich(self, event):
        raise RuntimeError('boom')


def _event(attributes=None):
    attrs = {'event_type': 'x', 'schema_version': '1.0'}
    attrs.update(attributes or {})
    return AuditEvent(
        event_type='x',
        schema_version='1.0',
        body='evt',
        attributes=attrs,
    )


def test_default_empty_pipeline_logs_normally():
    logger, capture = _make_logger()
    emit_event(logger, _event(), logging.INFO)
    assert len(capture.audit_records) == 1
    assert capture.audit_records[0].audit_attributes == {}


def test_filter_returning_false_drops_event():
    logger, capture = _make_logger()
    pipeline = AuditPipeline(filters=(_DropIfMarked(),))
    emit_event(
        logger,
        _event({'drop': True}),
        logging.INFO,
        pipeline=pipeline,
    )
    assert capture.audit_records == []


def test_filter_returning_true_keeps_event():
    logger, capture = _make_logger()
    pipeline = AuditPipeline(filters=(_DropIfMarked(),))
    emit_event(
        logger,
        _event(),
        logging.INFO,
        pipeline=pipeline,
    )
    assert len(capture.audit_records) == 1


def test_filter_raising_does_not_drop_event():
    logger, capture = _make_logger()
    pipeline = AuditPipeline(filters=(_RaiseFilter(),))
    emit_event(
        logger,
        _event(),
        logging.INFO,
        pipeline=pipeline,
    )
    assert len(capture.audit_records) == 1


def test_enricher_adds_fields():
    logger, capture = _make_logger()
    pipeline = AuditPipeline(enrichers=(_AddField('service.tag', 'billing'),))
    emit_event(
        logger,
        _event(),
        logging.INFO,
        pipeline=pipeline,
    )
    assert capture.audit_records[0].audit_attributes == {'service.tag': 'billing'}


def test_enricher_raising_is_skipped_and_prior_attrs_kept():
    logger, capture = _make_logger()
    pipeline = AuditPipeline(enrichers=(_RaiseEnricher(), _AddField('added', 'yes')))
    emit_event(
        logger,
        _event(),
        logging.INFO,
        pipeline=pipeline,
    )
    attrs = capture.audit_records[0].audit_attributes
    # the failing enricher is skipped; the next one still runs
    assert attrs == {'added': 'yes'}


def test_enricher_output_is_scrubbed_for_sensitive_keys():
    logger, capture = _make_logger()

    class _InjectPassword:
        def enrich(self, event):
            return {'password': 'secret'}

    pipeline = AuditPipeline(enrichers=(_InjectPassword(),))
    emit_event(
        logger,
        _event(),
        logging.INFO,
        pipeline=pipeline,
    )
    assert capture.audit_records[0].audit_attributes['password'] != 'secret'


def test_audit_pipeline_is_immutable():
    pipeline = AuditPipeline()
    with pytest.raises((AttributeError, Exception)):
        pipeline.filters = (_DropIfMarked(),)  # type: ignore[misc]


def test_from_sequences_copies_into_tuples():
    pipeline = AuditPipeline.from_sequences(
        filters=[_DropIfMarked()],
        enrichers=[_AddField('a', 'b')],
    )
    assert isinstance(pipeline.filters, tuple)
    assert isinstance(pipeline.enrichers, tuple)
    assert len(pipeline.filters) == 1
    assert len(pipeline.enrichers) == 1


def test_runtime_emit_threads_pipeline_through():
    logger, capture = _make_logger()
    runtime = LoggingRuntime(
        logger=logger,
        pipeline=AuditPipeline(enrichers=(_AddField('added', 'yes'),)),
    )
    runtime.emit_event(_event(), logging.INFO)
    assert len(capture.audit_records) == 1
    assert capture.audit_records[0].audit_attributes['added'] == 'yes'


def test_emit_rejects_non_event():
    logger, _ = _make_logger()
    with pytest.raises(TypeError):
        emit_event(logger, object(), logging.INFO)  # type: ignore[arg-type]


def test_emit_rejects_non_int_level():
    logger, _ = _make_logger()
    with pytest.raises(TypeError):
        emit_event(logger, _event(), 'INFO')  # type: ignore[arg-type]


def test_audit_pipeline_default_fields_are_empty_tuples():
    pipeline = AuditPipeline()
    assert pipeline.filters == ()
    assert pipeline.enrichers == ()


def test_protocols_are_runtime_checkable():
    from sec_audit.logging.protocols import AuditEnricher, AuditFilter

    assert isinstance(_DropIfMarked(), AuditFilter)
    assert isinstance(_AddField('k', 'v'), AuditEnricher)

    class _NotAFilter:
        pass

    assert not isinstance(_NotAFilter(), AuditFilter)
