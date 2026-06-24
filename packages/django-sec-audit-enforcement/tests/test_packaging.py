"""Admin templates must ship as package data (the Block manager view renders them)."""

from importlib.resources import files


def test_block_manager_templates_are_bundled():
    base = files('sec_audit.django_enforcement').joinpath(
        'templates/admin/sec_audit_enforcement/permanentblock'
    )
    assert base.joinpath('block_manager.html').is_file()
    assert base.joinpath('change_list.html').is_file()
