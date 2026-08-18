from phishing_detector import analyze_email


def test_benign_message_has_low_risk() -> None:
    result = analyze_email("Hi team, the meeting notes are attached. Thanks, Darsh")

    assert result.score == 0
    assert result.severity == "Low"
    assert result.indicators == ()


def test_credential_urgency_and_ip_link_are_explained() -> None:
    result = analyze_email(
        "Urgent: verify your account password at http://198.51.100.8/login"
    )

    codes = {indicator.code for indicator in result.indicators}
    assert result.severity == "Critical"
    assert result.score == 88
    assert result.urls_analyzed == 1
    assert {
        "credential_request",
        "urgency",
        "cleartext_http",
        "ip_address_host",
    } <= codes


def test_repeated_phrases_do_not_multiply_category_weight() -> None:
    result = analyze_email("urgent urgent urgent")

    assert result.score == 18
    assert [item.code for item in result.indicators] == ["urgency"]


def test_url_signals_are_deduplicated_across_links() -> None:
    result = analyze_email("Visit http://example.com or http://docs.example.com")

    assert result.score == 14
    assert [item.code for item in result.indicators] == ["cleartext_http"]
    assert result.urls_analyzed == 2


def test_punycode_shortener_and_encoded_url_rules() -> None:
    punycode = analyze_email("Open https://xn--pple-43d.example/a%2Fb")
    shortener = analyze_email("Open https://bit.ly/example")

    assert {item.code for item in punycode.indicators} == {
        "encoded_url",
        "punycode_host",
    }
    assert [item.code for item in shortener.indicators] == ["shortened_url"]


def test_score_is_capped_at_one_hundred() -> None:
    result = analyze_email(
        "Urgent final warning: verify your password for the bank account and claim "
        "your prize at http://203.0.113.10/a%2Fb"
    )

    assert result.score == 100
    assert result.severity == "Critical"


def test_result_can_be_serialized() -> None:
    payload = analyze_email("Hello").to_dict()

    assert payload["score"] == 0
    assert payload["urls_analyzed"] == 0
    assert payload["indicators"] == ()
