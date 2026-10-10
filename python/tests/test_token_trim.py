"""Pins the CLOUD_POSTURE_TOKEN trim rule of nimbus.server._require_token (verify-3 item
12 / V3-cli defect 10): the configured token is stripped like the Go server does, and a
whitespace-only token disables the endpoint (501) instead of accepting "Bearer "."""
import pytest
from fastapi import HTTPException

from nimbus.server import _require_token


def _status(authorization):
    try:
        _require_token(authorization)
    except HTTPException as e:
        return e.status_code
    return 200


def test_token_with_surrounding_spaces_is_trimmed(monkeypatch):
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", "  abc \n")
    assert _status("Bearer abc") == 200
    assert _status("Bearer  abc \n") == 401
    assert _status("Bearer abcd") == 401
    assert _status("bearer abc") == 401
    assert _status(None) == 401


@pytest.mark.parametrize("value", ["", " ", "\t\n  "])
def test_whitespace_only_token_disables_endpoint(monkeypatch, value):
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", value)
    assert _status("Bearer ") == 501
    assert _status("Bearer " + value) == 501
    assert _status(None) == 501
