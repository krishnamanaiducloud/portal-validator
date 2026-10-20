"""Bot-protection challenges are classified as such, never as authentication failures."""

import pytest

from app.navigation import browser_challenge_signal, classify_authentication


def classify(status, url, mode="none"):
    return classify_authentication(
        authentication_mode=mode, status=status, final_url=url,
        target_in_scope=True, error_classification=None,
    )


@pytest.mark.parametrize("status", [403, 429, 503])
def test_challenge_token_on_a_blocking_status_is_a_browser_challenge(status):
    assert classify(status, "https://site.example/?__cf_chl_rt_tk=opaque") == "CHALLENGE_REQUIRED"
    assert classify(status, "https://site.example/path?captcha_token=x&q=1") == "CHALLENGE_REQUIRED"


def test_plain_forbidden_without_challenge_evidence_stays_access_restricted():
    assert classify(403, "https://site.example/private") == "ACCESS_RESTRICTED"


def test_challenge_token_on_a_successful_page_is_not_a_challenge():
    assert classify(200, "https://site.example/?challenge_token=x") != "CHALLENGE_REQUIRED"


def test_challenge_signal_reads_only_parameter_names():
    assert browser_challenge_signal("https://site.example/?__CF_CHL_TK=a")
    assert not browser_challenge_signal("https://site.example/challenge?token=a")
    assert not browser_challenge_signal("not a url")
