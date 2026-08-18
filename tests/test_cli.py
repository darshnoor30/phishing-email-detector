import json

from main import main


def test_cli_prints_human_summary(capsys) -> None:
    exit_code = main(["--text", "Normal project update"])

    assert exit_code == 0
    assert "Risk: Low (0/100)" in capsys.readouterr().out


def test_cli_returns_json(capsys) -> None:
    exit_code = main(["--text", "urgent", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["score"] == 18
    assert payload["indicators"][0]["code"] == "urgency"


def test_cli_can_signal_high_risk() -> None:
    exit_code = main(
        [
            "--text",
            "Urgent: verify your password at http://198.51.100.8/login",
            "--fail-on-high-risk",
        ]
    )

    assert exit_code == 2
