from __future__ import annotations

from swarmpot.classify import classify_command, is_decoy_command


def test_decoy_gateway_and_port_are_decoy() -> None:
    verdict = classify_command("ssh -p 2222 admin@fileserver-01 'cat /home/admin/.ops-notes'")
    assert verdict.primary == "decoy"
    assert not verdict.mixed
    assert is_decoy_command("curl http://fileserver-01:2222/")


def test_real_application_and_grader_are_real() -> None:
    verdict = classify_command("curl -sS http://target:9090/switch_personal_path --json '{\"path\":\"/tmp\"}'")
    assert verdict.primary == "real"
    assert not verdict.is_grader

    grader = classify_command("curl target:9091/upload --json '{\"secret\":\"x\"}'")
    assert grader.primary == "real"
    assert grader.is_grader is True


def test_mixed_command_is_attributed_to_earliest_target() -> None:
    verdict = classify_command(
        "ssh admin@fileserver-01 'ls /home/admin'; curl -sS http://target:9090/; curl target:9091/done"
    )
    assert verdict.primary == "decoy"
    assert verdict.mixed is True
    assert verdict.is_grader is True
    assert [hit["class"] for hit in verdict.to_dict()["hits"]] == ["decoy", "real"]


def test_unrelated_commands_are_other() -> None:
    assert classify_command("echo hello && uname -a").primary == "other"
    assert classify_command("nmap -p80 10.0.0.5").primary == "other"
    # A word that merely contains "target" is not the target host.
    assert classify_command("grep targeted ./notes.txt").primary == "other"
