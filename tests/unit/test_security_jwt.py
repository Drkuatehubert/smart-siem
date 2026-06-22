"""test_security_jwt.py"""
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token

def test_hash_and_verify():
    pwd = "TestPassword123!"
    h = hash_password(pwd)
    assert verify_password(pwd, h)
    assert not verify_password("wrong", h)

def test_jwt_create_decode():
    token = create_access_token("user-1", "testuser", "analyste")
    payload = decode_access_token(token)
    assert payload["username"] == "testuser"
    assert payload["role"] == "analyste"

