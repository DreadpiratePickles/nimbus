"""Verification 7 defect 11: compliance scores are rounded, not truncated, in Go and Python alike."""
from nimbus.compliance.engine import score_percent


def test_score_percent_rounds_like_go():
    assert score_percent(4, 7) == 36.4
    assert score_percent(2, 1) == 66.7
    assert score_percent(1, 2) == 33.3
    assert score_percent(3, 9) == 25.0
    assert score_percent(0, 0) == 0.0
