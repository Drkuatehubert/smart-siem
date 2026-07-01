"""test_rbac.py"""
from app.core.rbac import has_permission, Role

def test_admin_has_all():
    assert has_permission(Role.ADMINISTRATEUR, "audit:read")
    assert has_permission(Role.ADMINISTRATEUR, "users:create")

def test_lecteur_read_only():
    assert has_permission(Role.LECTEUR, "logs:read")
    assert not has_permission(Role.LECTEUR, "alerts:update")
    assert not has_permission(Role.LECTEUR, "audit:read")

def test_analyste_limited():
    assert has_permission(Role.ANALYSTE, "alerts:update")
    assert not has_permission(Role.ANALYSTE, "users:create")
    assert not has_permission(Role.ANALYSTE, "audit:read")

