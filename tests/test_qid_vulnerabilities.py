from __future__ import annotations

from io import StringIO
import logging
from logging.handlers import RotatingFileHandler
from urllib import parse

import pytest

from qualys_qid_vulnerabilities.errors import QualysResponseError
from qualys_qid_vulnerabilities.errors import QualysClientError
from qualys_qid_vulnerabilities.asset_search import AssetSearch
from qualys_qid_vulnerabilities import cli
from qualys_qid_vulnerabilities import progress as progress_module
from qualys_qid_vulnerabilities.client import (
    HOST_VULNERABILITY_DETECTION_PATH,
    HOST_LIST_PATH,
    IGNORE_VULNERABILITY_PATH,
    QidVulnerabilityClient,
)
from qualys_qid_vulnerabilities.ignore import (
    MAX_IGNORE_IPS_LENGTH,
    IgnoreRequestError,
    IgnoreVulnerabilityRequest,
    create_ignore_request_batches,
)
from qualys_qid_vulnerabilities.ip_filter import IpFilter, IpFilterError
from qualys_qid_vulnerabilities.models import (
    IgnoreVulnerabilityResult,
    IgnoredVulnerabilityRecord,
    QidVulnerabilityListing,
    QidVulnerabilityRecord,
)
from qualys_qid_vulnerabilities.host_list import parse_host_list
from qualys_qid_vulnerabilities.progress import ProgressDisplay
from qualys_qid_vulnerabilities import logging_setup
from qualys_qid_vulnerabilities.logging_setup import (
    LOG_BACKUP_COUNT,
    MAX_LOG_BYTES,
    configure_logging,
)


HOST_DETECTION_XML = b"""\
<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ID>101</ID>
        <ASSET_ID>asset-001</ASSET_ID>
        <IP>192.0.2.10</IP>
        <DNS>server-one.example.test</DNS>
        <DETECTION_LIST>
          <DETECTION>
            <UNIQUE_VULN_ID>900001</UNIQUE_VULN_ID>
            <QID>12345</QID>
            <STATUS>Active</STATUS>
          </DETECTION>
          <DETECTION>
            <UNIQUE_VULN_ID>900002</UNIQUE_VULN_ID>
            <QID>12345</QID>
            <STATUS>New</STATUS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <ID>102</ID>
        <ASSET_ID>asset-002</ASSET_ID>
        <IP>192.0.2.11</IP>
        <DNS_DATA><HOSTNAME>server-two</HOSTNAME></DNS_DATA>
        <DETECTION_LIST>
          <DETECTION>
            <QID>12345</QID>
            <STATUS>Fixed</STATUS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

HOST_LIST_XML = b"""\
<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>101</ID><ASSET_ID>100001</ASSET_ID><IP>192.0.2.10</IP>
    <DNS>Server-One.Example.Test.</DNS>
    <DNS_DATA><HOSTNAME>server-one</HOSTNAME><FQDN>server-one.example.test</FQDN></DNS_DATA>
  </HOST>
  <HOST><ID>102</ID><ASSET_ID>100002</ASSET_ID><IP>192.0.2.11</IP><DNS>other.test</DNS></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_OUTPUT>
"""


def test_asset_search_matches_asset_id_and_dns_values_case_insensitively() -> None:
    assets = parse_host_list(HOST_LIST_XML)
    assert AssetSearch.parse(asset_ids="100001", hostnames=None).matches(
        asset_id=assets[0].asset_id, hostnames=assets[0].hostnames
    )
    assert AssetSearch.parse(asset_ids=None, hostnames="server-one.example.test").matches(
        asset_id=assets[0].asset_id, hostnames=assets[0].hostnames
    )
    assert not AssetSearch.parse(asset_ids=None, hostnames="missing.test").matches(
        asset_id=assets[0].asset_id, hostnames=assets[0].hostnames
    )

HOST_WITHOUT_QID_XML = b"""\
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ASSET_ID>asset-001</ASSET_ID>
        <IP>192.0.2.10</IP>
        <DNS>server-one.example.test</DNS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>54321</QID>
            <STATUS>Active</STATUS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

NO_HOSTS_XML = b"""\
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE />
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

VERIFICATION_XML = b"""\
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ASSET_ID>asset-ignored</ASSET_ID><IP>192.0.2.10</IP><DNS>ignored.test</DNS>
        <DETECTION_LIST>
          <DETECTION><UNIQUE_VULN_ID>1</UNIQUE_VULN_ID><QID>12345</QID><STATUS>Active</STATUS><IS_IGNORED>1</IS_IGNORED></DETECTION>
          <DETECTION><UNIQUE_VULN_ID>2</UNIQUE_VULN_ID><QID>12345</QID><STATUS>Active</STATUS><IS_IGNORED>1</IS_IGNORED></DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <ASSET_ID>asset-not-ignored</ASSET_ID><IP>192.0.2.11</IP>
        <DETECTION_LIST>
          <DETECTION><UNIQUE_VULN_ID>3</UNIQUE_VULN_ID><QID>12345</QID><STATUS>New</STATUS><IS_IGNORED>0</IS_IGNORED></DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <ASSET_ID>asset-unknown</ASSET_ID><IP>192.0.2.12</IP>
        <DETECTION_LIST>
          <DETECTION><UNIQUE_VULN_ID>4</UNIQUE_VULN_ID><QID>12345</QID><STATUS>Fixed</STATUS><IS_IGNORED>1</IS_IGNORED></DETECTION>
          <DETECTION><UNIQUE_VULN_ID>5</UNIQUE_VULN_ID><QID>12345</QID><STATUS>Fixed</STATUS><IS_IGNORED>unexpected</IS_IGNORED></DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <ASSET_ID>asset-without-qid</ASSET_ID><IP>192.0.2.13</IP>
        <DETECTION_LIST>
          <DETECTION><QID>54321</QID><STATUS>Active</STATUS><IS_IGNORED>0</IS_IGNORED></DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

IGNORE_SUCCESS_XML = b"""\
<IGNORE_VULN_OUTPUT>
  <RESPONSE status="SUCCESS" number="2">
    <MESSAGE>The operation was successfully completed</MESSAGE>
    <IGNORED_LIST>
      <IGNORED>
        <TICKET_NUMBER>16</TICKET_NUMBER>
        <QID>12345</QID>
        <IP>192.0.2.10</IP>
        <DNS>server-one.example.test</DNS>
      </IGNORED>
      <IGNORED>
        <TICKET_NUMBER>17</TICKET_NUMBER>
        <QID>12345</QID>
        <IP>192.0.2.11</IP>
      </IGNORED>
    </IGNORED_LIST>
  </RESPONSE>
</IGNORE_VULN_OUTPUT>
"""


def test_progress_display_reports_operation_and_elapsed_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic_values = iter((0.0, 0.0, 65.0))
    monkeypatch.setattr(
        progress_module.time,
        "monotonic",
        lambda: next(monotonic_values),
    )
    stream = StringIO()

    with ProgressDisplay(stream=stream).step("Querying Qualys"):
        pass

    assert stream.getvalue() == (
        "[00:00] Querying Qualys...\n"
        "[01:05] done: Querying Qualys\n"
    )


def test_progress_display_can_use_discrete_lines_for_verbose_output() -> None:
    stream = StringIO()

    with ProgressDisplay(stream=stream, interactive=False).step("Querying Qualys"):
        stream.write("verbose diagnostic\n")

    assert stream.getvalue().splitlines() == [
        "[00:00] Querying Qualys...",
        "verbose diagnostic",
        "[00:00] done: Querying Qualys",
    ]


def test_verbose_logging_is_disabled_on_stderr_by_default(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    logger = configure_logging(log_file=str(tmp_path / "qid.log"))
    logger.info("hidden diagnostic")
    logger.warning("visible warning")

    captured = capsys.readouterr()
    assert "hidden diagnostic" not in captured.err
    assert "visible warning" in captured.err


def test_verbose_logging_is_readable_and_rotating_file_is_bounded(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "qid.log"
    logger = configure_logging(verbose=True, log_file=str(log_path))
    logger.info("diagnostic without credentials")

    captured = capsys.readouterr()
    assert "INFO" in captured.err
    assert "diagnostic without credentials" in captured.err
    assert "diagnostic without credentials" in log_path.read_text()
    handler = next(
        handler
        for handler in logger.handlers
        if isinstance(handler, RotatingFileHandler)
    )
    assert handler.maxBytes == MAX_LOG_BYTES
    assert handler.backupCount == LOG_BACKUP_COUNT


def test_terminal_log_wraps_under_message_start() -> None:
    formatter = logging_setup.TerminalFormatter(
        colour=False,
        width=60,
        compact_logger=True,
    )
    record = logging.LogRecord(
        "qualys_qid_vulnerabilities.transport",
        logging.INFO,
        "transport.py",
        1,
        "Response from a very long endpoint https://qualys.example.test/api/5.0/fo/asset/host/vm/detection/ completed",
        (),
        None,
    )

    lines = formatter.format(record).splitlines()
    message_start = lines[0].index(": ") + 2
    assert all(len(line) <= 60 for line in lines)
    assert all(line.startswith(" " * message_start) for line in lines[1:])


def test_cli_parser_accepts_verbose_for_read_only_and_ignore_commands() -> None:
    parser = cli.build_parser()

    for argv in (
        ["12345", "--verify-ignored", "--verbose"],
        [
            "12345",
            "--ips",
            "192.0.2.10",
            "--ignore",
            "--comment",
            "approved",
            "--verbose",
        ],
    ):
        args = parser.parse_args(argv)
        assert args.verbose is True


def test_cli_help_is_grouped_and_includes_quick_start_examples() -> None:
    help_text = cli.build_parser().format_help()

    assert "usage: qid [QID] [OPTIONS]" in help_text
    assert "target scope (choose at most one):" in help_text
    assert "read-only modes:" in help_text
    assert "ignore workflow (changes Qualys state):" in help_text
    assert "configuration and diagnostics:" in help_text
    assert 'qid 12345 --ips "192.0.2.10-192.0.2.20"' in help_text
    assert "local DNS is not queried" in help_text


def test_cli_question_mark_shows_help(capsys) -> None:
    assert cli.main(["?"]) == 0
    assert "usage: qid [QID] [OPTIONS]" in capsys.readouterr().out


def test_cli_logs_displays_default_log(tmp_path, monkeypatch, capsys) -> None:
    log_path = tmp_path / "qid.log"
    log_path.write_text("first log entry\nsecond log entry\n")
    monkeypatch.setattr(logging_setup, "DEFAULT_LOG_FILE", log_path)

    assert cli.main(["logs"]) == 0
    assert capsys.readouterr().out == "first log entry\nsecond log entry\n"


def test_cli_logs_accepts_custom_log_file(tmp_path, capsys) -> None:
    log_path = tmp_path / "custom.log"
    log_path.write_text("custom log entry")

    assert cli.main(["logs", "--log-file", str(log_path)]) == 0
    assert capsys.readouterr().out == "custom log entry\n"


def test_cli_logs_reports_missing_log(capsys, tmp_path, monkeypatch) -> None:
    log_path = tmp_path / "missing.log"
    monkeypatch.setattr(logging_setup, "DEFAULT_LOG_FILE", log_path)

    assert cli.main(["logs"]) == 1
    assert "could not read log file" in capsys.readouterr().err


def test_cli_man_opens_bundled_manual(monkeypatch) -> None:
    calls = []

    def fake_run(command, *, check):
        calls.append((command, check))
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.main(["--man"]) == 0
    assert calls[0][0][:2] == ["man", "-l"]
    assert calls[0][1] is False


def test_cli_interrupt_exits_without_traceback(tmp_path, monkeypatch, capsys) -> None:
    def interrupt(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.AppConfig, "load", interrupt)

    log_path = tmp_path / "qid.log"
    assert cli.main(["12345", "--log-file", str(log_path)]) == 130
    error = capsys.readouterr().err
    assert "failed: Loading and validating runtime configuration" in error
    assert "Interrupted; no Qualys changes were made." in error
    assert "Traceback" not in error
    assert "COMMAND INTERRUPTED | qid=12345 | mode=lookup" in log_path.read_text()


def test_logging_writes_to_private_default_log(tmp_path, monkeypatch) -> None:
    default_log = tmp_path / "state" / "qid.log"
    monkeypatch.setattr(logging_setup, "DEFAULT_LOG_FILE", default_log)
    logger = configure_logging()
    logger.info("background diagnostic")

    assert default_log.exists()
    assert "background diagnostic" in default_log.read_text()
    assert default_log.stat().st_mode & 0o777 == 0o600


def test_default_log_does_not_nest_when_started_from_logs(tmp_path, monkeypatch) -> None:
    project_root = tmp_path / "project"
    logs_dir = project_root / "logs"
    logs_dir.mkdir(parents=True)
    monkeypatch.setattr(logging_setup, "DEFAULT_LOG_FILE", logs_dir / "qid.log")
    monkeypatch.chdir(logs_dir)

    logger = configure_logging()
    logger.info(
        "request URL remains on one line: "
        "https://qualys.example.test/api/5.0/fo/asset/host/vm/detection/"
    )

    log_path = logs_dir / "qid.log"
    assert log_path.exists()
    assert not (logs_dir / "logs" / "qid.log").exists()
    log_text = log_path.read_text()
    assert len(log_text.splitlines()) == 1
    assert "https://qualys.example.test/api/5.0/fo/asset/host/vm/detection/" in log_text


def test_file_log_uses_compact_component_columns_and_command_gaps(tmp_path) -> None:
    log_path = tmp_path / "qid.log"
    logger = configure_logging(log_file=str(log_path))
    logger.info("BEGIN COMMAND | qid=39008 | mode=lookup")
    logger.info("request completed")
    logger.info("BEGIN COMMAND | qid=39008 | mode=verify-ignored")

    lines = log_path.read_text().splitlines()
    assert lines[0] == ""
    assert "| INFO     | qualys_qid_vulnerabilities | BEGIN COMMAND | qid=39008 | mode=lookup" in lines[1]
    assert "| INFO     | qualys_qid_vulnerabilities | request completed" in lines[2]
    assert lines[3] == ""
    assert "mode=verify-ignored" in lines[4]


@pytest.mark.parametrize(
    ("raw_value", "expected_value", "expected_count"),
    [
        ("192.168.0.200", "192.168.0.200", 1),
        (
            "192.168.0.10,192.168.0.20,192.168.0.30",
            "192.168.0.10,192.168.0.20,192.168.0.30",
            3,
        ),
        (
            "192.168.0.87-192.168.0.92",
            "192.168.0.87-192.168.0.92",
            1,
        ),
        (
            "192.168.0.87-192.168.0.92,192.168.0.200",
            "192.168.0.87-192.168.0.92,192.168.0.200",
            2,
        ),
        (
            " 192.168.0.87 - 192.168.0.92 ,  192.168.0.200 ",
            "192.168.0.87-192.168.0.92,192.168.0.200",
            2,
        ),
    ],
)
def test_ip_filter_normalizes_supported_inputs_without_expanding_ranges(
    raw_value: str,
    expected_value: str,
    expected_count: int,
) -> None:
    ip_filter = IpFilter.parse(raw_value)

    assert ip_filter.qualys_value == expected_value
    assert ip_filter.requested_count == expected_count


@pytest.mark.parametrize("raw_value", ["192.168.0.999", "not-an-ip", "2001:db8::1"])
def test_ip_filter_rejects_invalid_ipv4_addresses(raw_value: str) -> None:
    with pytest.raises(IpFilterError, match="invalid IPv4 address"):
        IpFilter.parse(raw_value)


@pytest.mark.parametrize("raw_value", ["192.168.0.1-", "-192.168.0.2"])
def test_ip_filter_rejects_incomplete_ranges(raw_value: str) -> None:
    with pytest.raises(IpFilterError, match="incomplete IPv4 range"):
        IpFilter.parse(raw_value)


def test_ip_filter_rejects_reversed_ranges() -> None:
    with pytest.raises(IpFilterError, match="ending address lower"):
        IpFilter.parse("192.168.0.92-192.168.0.87")


@pytest.mark.parametrize("raw_value", ["", "   "])
def test_ip_filter_rejects_empty_input(raw_value: str) -> None:
    with pytest.raises(IpFilterError, match="must not be empty"):
        IpFilter.parse(raw_value)


def test_listing_parses_detection_fields_and_counts_unique_assets() -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        HOST_DETECTION_XML,
        requested_qid=12345,
    )

    assert listing.affected_asset_count == 2
    assert listing.matched_asset_count == 2
    assert len(listing.vulnerabilities) == 3
    assert listing.vulnerabilities[0].asset_id == "asset-001"
    assert listing.vulnerabilities[0].dns_hostname == "server-one.example.test"
    assert listing.vulnerabilities[0].vulnerability_id == "900001"
    assert listing.vulnerabilities[2].dns_hostname == "server-two"
    assert listing.vulnerabilities[2].vulnerability_id is None


def test_empty_detection_response_is_a_valid_empty_result() -> None:
    listing = QidVulnerabilityListing.from_api_xml(b"", requested_qid=12345)

    assert listing.vulnerabilities == ()
    assert listing.matched_asset_count == 0


def test_listing_surfaces_qualys_xml_error_response() -> None:
    payload = b"""\
    <SIMPLE_RETURN>
      <RESPONSE><CODE>1901</CODE><TEXT>Invalid QID</TEXT></RESPONSE>
    </SIMPLE_RETURN>
    """

    with pytest.raises(QualysResponseError, match="1901: Invalid QID"):
        QidVulnerabilityListing.from_api_xml(payload, requested_qid=12345)


def test_listing_distinguishes_no_assets_from_assets_without_requested_qid() -> None:
    no_assets = QidVulnerabilityListing.from_api_xml(
        NO_HOSTS_XML,
        requested_qid=12345,
    )
    no_vulnerabilities = QidVulnerabilityListing.from_api_xml(
        HOST_WITHOUT_QID_XML,
        requested_qid=12345,
    )

    assert no_assets.matched_asset_count == 0
    assert no_assets.affected_asset_count == 0
    assert no_assets.vulnerabilities == ()
    assert no_vulnerabilities.matched_asset_count == 1
    assert no_vulnerabilities.affected_asset_count == 0
    assert no_vulnerabilities.vulnerabilities == ()


def test_listing_classifies_ignored_state_and_unique_asset_totals() -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        VERIFICATION_XML,
        requested_qid=12345,
    )

    assert [record.ignored_state for record in listing.vulnerabilities] == [
        "ignored",
        "ignored",
        "not ignored",
        "ignored",
        "unknown",
    ]
    assert listing.matched_asset_count == 4
    assert listing.affected_asset_count == 3
    assert listing.confirmed_ignored_asset_count == 1
    assert listing.not_ignored_asset_count == 1
    assert listing.unknown_ignore_state_asset_count == 1
    assert [asset.asset_id for asset in listing.assets_without_requested_qid] == [
        "asset-without-qid"
    ]


@pytest.mark.parametrize("ignored_xml", ["", "<IS_IGNORED>bad</IS_IGNORED>"])
def test_listing_treats_missing_or_malformed_ignored_state_as_unknown(
    ignored_xml: str,
) -> None:
    payload = f"""\
    <HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST>
      <ASSET_ID>asset-001</ASSET_ID><IP>192.0.2.10</IP>
      <DETECTION_LIST><DETECTION><QID>12345</QID><STATUS>Active</STATUS>
      {ignored_xml}</DETECTION></DETECTION_LIST>
    </HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>
    """.encode()

    listing = QidVulnerabilityListing.from_api_xml(payload, requested_qid=12345)

    assert listing.vulnerabilities[0].ignored is None
    assert listing.unknown_ignore_state_asset_count == 1


def test_client_uses_read_only_host_detection_list_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return HOST_DETECTION_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)

    listing = client.get_vulnerabilities_for_qid(
        12345,
        ip_filter=IpFilter.parse(
            "192.168.0.87-192.168.0.92, 192.168.0.200"
        ),
    )

    assert len(listing.vulnerabilities) == 3
    assert captured["base_url"] == "https://qualysapi.example.test"
    assert captured["path"] == HOST_VULNERABILITY_DETECTION_PATH
    assert captured["form"] == {
        "action": "list",
        "qids": "12345",
        "ips": "192.168.0.87-192.168.0.92,192.168.0.200",
        "show_asset_id": "1",
        "truncation_limit": "0",
    }
    assert captured["accept"] == "application/xml"
    assert parse.unquote(captured["headers"]["Authorization"]).startswith("Basic ")


def test_client_can_query_a_qid_across_all_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return HOST_DETECTION_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)

    listing = client.get_vulnerabilities_for_qid(12345)

    assert len(listing.vulnerabilities) == 3
    assert captured["form"] == {
        "action": "list",
        "qids": "12345",
        "show_asset_id": "1",
        "truncation_limit": "0",
    }


def test_client_can_query_all_qids_for_a_selected_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return HOST_DETECTION_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)

    listing = client.get_vulnerabilities_for_qid(
        None,
        ip_filter=IpFilter.parse("192.0.2.10"),
    )

    assert len(listing.vulnerabilities) == 3
    assert captured["form"] == {
        "action": "list",
        "ips": "192.0.2.10",
        "show_asset_id": "1",
        "truncation_limit": "0",
    }


def test_client_searches_asset_id_and_hostname_using_read_only_host_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return HOST_LIST_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)

    assets = client.search_assets(
        AssetSearch.parse(asset_ids=None, hostnames="server-one.example.test")
    )

    assert [asset.asset_id for asset in assets] == ["100001"]
    assert assets[0].ip_address == "192.0.2.10"
    assert captured["path"] == HOST_LIST_PATH
    assert captured["form"] == {
        "action": "list",
        "details": "Basic",
        "show_asset_id": "1",
        "truncation_limit": "0",
    }


def test_client_verification_includes_ignored_detections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return VERIFICATION_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)

    client.get_vulnerabilities_for_qid(
        12345,
        ip_filter=IpFilter.parse("192.0.2.10-192.0.2.13"),
        include_ignored=True,
    )

    assert captured["form"] == {
        "action": "list",
        "qids": "12345",
        "ips": "192.0.2.10-192.0.2.13",
        "show_asset_id": "1",
        "truncation_limit": "0",
        "include_ignored": "1",
    }


def test_client_uses_scoped_ignore_request_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return IGNORE_SUCCESS_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)
    request = IgnoreVulnerabilityRequest.create(
        qid=12345,
        ip_addresses=("192.0.2.10", "192.0.2.10", "192.0.2.11"),
        comments="Approved exception CHG001234",
    )

    result = client.ignore_vulnerabilities(request)

    assert result.affected_ip_count == 2
    assert len(result.ignored) == 2
    assert captured["base_url"] == "https://qualysapi.example.test"
    assert captured["path"] == IGNORE_VULNERABILITY_PATH
    assert captured["form"] == {
        "action": "ignore",
        "qids": "12345",
        "ips": "192.0.2.10,192.0.2.11",
        "comments": "Approved exception CHG001234",
    }
    assert captured["accept"] == "application/xml"


def test_client_sends_temporary_ignore_reopen_days(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = QidVulnerabilityClient(
        base_url="https://gateway.example.test",
        auth_model="basic",
        timeout_seconds=30,
        verify_ssl=True,
        username="alice",
        password="secret",
    )
    captured: dict[str, object] = {}

    def fake_post_form(**kwargs):
        captured.update(kwargs)
        return IGNORE_SUCCESS_XML

    monkeypatch.setattr(client, "_post_form", fake_post_form)
    request = IgnoreVulnerabilityRequest.create(
        qid=12345,
        ip_addresses=("192.0.2.10", "192.0.2.11"),
        comments="Temporary exception CHG001234",
        reopen_ignored_days=30,
    )

    client.ignore_vulnerabilities(request)

    assert captured["form"] == {
        "action": "ignore",
        "qids": "12345",
        "ips": "192.0.2.10,192.0.2.11",
        "comments": "Temporary exception CHG001234",
        "reopen_ignored_days": "30",
    }


def test_ignore_response_rejects_non_success_status() -> None:
    payload = b"""\
    <IGNORE_VULN_OUTPUT>
      <RESPONSE status="FAILED">
        <MESSAGE>Not authorized to ignore vulnerabilities</MESSAGE>
      </RESPONSE>
    </IGNORE_VULN_OUTPUT>
    """

    with pytest.raises(QualysResponseError, match="FAILED.*Not authorized"):
        IgnoreVulnerabilityResult.from_api_xml(
            payload,
            requested_qid=12345,
            requested_ips=("192.0.2.10",),
        )


def test_ignore_request_rejects_target_scope_over_qualys_limit() -> None:
    ip_addresses = tuple(f"10.0.0.{value}" for value in range(1, 60))

    with pytest.raises(IgnoreRequestError, match="512-character"):
        IgnoreVulnerabilityRequest.create(
            qid=12345,
            ip_addresses=ip_addresses,
            comments="Approved exception CHG001234",
        )


def test_ignore_request_batches_preserve_exact_scope_within_qualys_limit() -> None:
    ip_addresses = tuple(f"10.0.0.{value}" for value in range(1, 60))

    batches = create_ignore_request_batches(
        qid=12345,
        ip_addresses=ip_addresses + ("10.0.0.1",),
        comments="Approved exception CHG001234",
    )

    assert len(batches) == 2
    assert tuple(
        ip_address
        for batch in batches
        for ip_address in batch.ip_addresses
    ) == ip_addresses
    assert all(
        len(batch.qualys_ips_value.encode("ascii")) <= MAX_IGNORE_IPS_LENGTH
        for batch in batches
    )
    assert {batch.qid for batch in batches} == {12345}
    assert {batch.comments for batch in batches} == {
        "Approved exception CHG001234"
    }
    assert {batch.reopen_ignored_days for batch in batches} == {None}


@pytest.mark.parametrize("days", [0, 731])
def test_ignore_request_rejects_invalid_reopen_days(days: int) -> None:
    with pytest.raises(IgnoreRequestError, match="between 1 and 730"):
        IgnoreVulnerabilityRequest.create(
            qid=12345,
            ip_addresses=("192.0.2.10",),
            comments="Temporary exception CHG001234",
            reopen_ignored_days=days,
        )


def test_cli_prints_table_and_totals(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        HOST_DETECTION_XML,
        requested_qid=12345,
    )
    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: type(
            "FakeClient",
            (),
            {
                "get_vulnerabilities_for_qid": (
                    lambda self, qid, *, ip_filter: listing
                )
            },
        )(),
    )

    assert cli.main(
        ["12345", "--ip", "192.0.2.10-192.0.2.11, 192.0.2.20"]
    ) == 0

    captured = capsys.readouterr()
    output = captured.out
    assert "Loading and validating runtime configuration" in captured.err
    assert "Querying Qualys for QID 12345 detections" in captured.err
    assert "done: Querying Qualys for QID 12345 detections" in captured.err
    assert "Asset ID" in output
    assert "server-one.example.test" in output
    assert "Matching vulnerability detections were found." in output
    assert "Total IPs or ranges requested: 2" in output
    assert "Total assets matched: 2" in output
    assert "Total assets affected: 2" in output
    assert "Total vulnerabilities found: 3" in output


@pytest.mark.parametrize("headers", [cli.HEADERS, cli.VERIFICATION_HEADERS])
def test_cli_formats_empty_query_tables(headers: tuple[str, ...]) -> None:
    output = cli._format_responsive_table(headers, [])

    assert headers[0] in output
    assert "-+-" in output


@pytest.mark.parametrize(
    ("payload", "expected_message", "expected_matched"),
    [
        (NO_HOSTS_XML, "No assets matched the supplied IP filter.", 0),
        (
            HOST_WITHOUT_QID_XML,
            "Assets matched the supplied IP filter, but QID 12345 was not found.",
            1,
        ),
    ],
)
def test_cli_distinguishes_no_assets_from_no_vulnerabilities(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: bytes,
    expected_message: str,
    expected_matched: int,
) -> None:
    empty = QidVulnerabilityListing.from_api_xml(payload, requested_qid=12345)
    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: type(
            "FakeClient",
            (),
            {
                "get_vulnerabilities_for_qid": (
                    lambda self, qid, *, ip_filter: empty
                )
            },
        )(),
    )

    assert cli.main(["12345", "--ips", "192.0.2.10"]) == 0

    output = capsys.readouterr().out
    assert expected_message in output
    assert "Asset ID" in output
    assert "Total IPs or ranges requested: 1" in output
    assert f"Total assets matched: {expected_matched}" in output
    assert "Total assets affected: 0" in output
    assert "Total vulnerabilities found: 0" in output


def test_cli_requires_ignore_comment_before_loading_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_loaded = False

    def fake_load(**kwargs):
        nonlocal config_loaded
        config_loaded = True

    monkeypatch.setattr(cli.AppConfig, "load", fake_load)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["12345", "--ips", "192.0.2.10", "--ignore"])

    assert exc_info.value.code == 2
    assert not config_loaded
    assert "--comment is required when --ignore is used" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("comment", "expected_error"),
    [
        ("", "must not be empty"),
        ("x" * 256, "must not exceed 255"),
    ],
)
def test_cli_validates_ignore_comment_before_loading_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    comment: str,
    expected_error: str,
) -> None:
    config_loaded = False

    def fake_load(**kwargs):
        nonlocal config_loaded
        config_loaded = True

    monkeypatch.setattr(cli.AppConfig, "load", fake_load)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            ["12345", "--ips", "192.0.2.10", "--ignore", "--comment", comment]
        )

    assert exc_info.value.code == 2
    assert not config_loaded
    assert expected_error in capsys.readouterr().err


def test_cli_cancelled_confirmation_sends_no_ignore_request(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        HOST_DETECTION_XML,
        requested_qid=12345,
    )

    class FakeClient:
        def get_vulnerabilities_for_qid(self, qid, *, ip_filter):
            return listing

        def ignore_vulnerabilities(self, request):
            raise AssertionError("ignore request must not be sent")

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "no")

    result = cli.main(
        [
            "12345",
            "--ips",
            "192.0.2.10-192.0.2.11",
            "--ignore",
            "--comment",
            "Approved exception CHG001234",
        ]
    )

    assert result == 1
    output = capsys.readouterr()
    assert "may close or create remediation tickets" in output.out
    assert "Ignore cancelled; no Qualys changes were made." in output.err


def test_cli_confirmed_ignore_targets_only_unique_returned_asset_ips(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        HOST_DETECTION_XML,
        requested_qid=12345,
    )
    captured: dict[str, object] = {}

    class FakeClient:
        def get_vulnerabilities_for_qid(self, qid, *, ip_filter):
            return listing

        def ignore_vulnerabilities(self, request):
            captured["request"] = request
            return IgnoreVulnerabilityResult(
                message="The operation was successfully completed",
                ignored=(
                    IgnoredVulnerabilityRecord(
                        ticket_number="16",
                        qid=12345,
                        ip_address="192.0.2.10",
                        dns_hostname="server-one.example.test",
                    ),
                    IgnoredVulnerabilityRecord(
                        ticket_number="17",
                        qid=12345,
                        ip_address="192.0.2.11",
                        dns_hostname="server-two",
                    ),
                ),
            )

    prompts: list[str] = []

    def confirm(prompt: str) -> str:
        prompts.append(prompt)
        return "IGNORE QID 12345"

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr("builtins.input", confirm)

    result = cli.main(
        [
            "12345",
            "--ips",
            "192.0.2.10-192.0.2.20",
            "--ignore",
            "--comment",
            "Approved exception CHG001234",
        ]
    )

    assert result == 0
    request = captured["request"]
    assert request.ip_addresses == ("192.0.2.10", "192.0.2.11")
    assert request.comments == "Approved exception CHG001234"
    assert request.reopen_ignored_days is None
    assert prompts == ["Type 'IGNORE QID 12345' to continue: "]
    captured_output = capsys.readouterr()
    output = captured_output.out
    assert (
        "Submitting confirmed ignore for QID 12345 to Qualys"
        in captured_output.err
    )
    assert (
        "done: Submitting confirmed ignore for QID 12345 to Qualys"
        in captured_output.err
    )
    assert "Total asset IPs confirmed ignored: 2" in output
    assert "Total ignore records returned: 2" in output
    assert "Automatic reopen: not set" in output


def test_cli_temporary_ignore_sets_and_displays_reopen_days(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        HOST_DETECTION_XML,
        requested_qid=12345,
    )
    captured: dict[str, IgnoreVulnerabilityRequest] = {}

    class FakeClient:
        def get_vulnerabilities_for_qid(self, qid, *, ip_filter):
            return listing

        def ignore_vulnerabilities(self, request):
            captured["request"] = request
            return IgnoreVulnerabilityResult(message="success", ignored=())

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "IGNORE QID 12345")

    result = cli.main(
        [
            "12345",
            "--ips",
            "192.0.2.10-192.0.2.11",
            "--ignore",
            "--comment",
            "Temporary exception CHG001234",
            "--reopen-after-days",
            "30",
        ]
    )

    assert result == 0
    assert captured["request"].reopen_ignored_days == 30
    assert "Automatic reopen: 30 day(s)" in capsys.readouterr().out


def test_cli_batches_large_confirmed_ignore_scope(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ip_addresses = tuple(f"10.0.0.{value}" for value in range(1, 60))
    listing = QidVulnerabilityListing(
        vulnerabilities=tuple(
            QidVulnerabilityRecord(
                asset_id=f"asset-{index}",
                ip_address=ip_address,
                dns_hostname=None,
                qid=12345,
                status="Active",
                vulnerability_id=str(index),
            )
            for index, ip_address in enumerate(ip_addresses, start=1)
        )
    )
    requests: list[IgnoreVulnerabilityRequest] = []

    class FakeClient:
        def get_vulnerabilities_for_qid(self, qid, *, ip_filter):
            return listing

        def ignore_vulnerabilities(self, request):
            requests.append(request)
            return IgnoreVulnerabilityResult(
                message="The operation was successfully completed",
                ignored=tuple(
                    IgnoredVulnerabilityRecord(
                        ticket_number=f"ticket-{index}",
                        qid=request.qid,
                        ip_address=ip_address,
                        dns_hostname=None,
                    )
                    for index, ip_address in enumerate(
                        request.ip_addresses,
                        start=1,
                    )
                ),
            )

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "IGNORE QID 12345")

    result = cli.main(
        [
            "12345",
            "--ips",
            "10.0.0.1-10.0.0.59",
            "--ignore",
            "--comment",
            "Approved exception CHG001234",
        ]
    )

    assert result == 0
    assert len(requests) == 2
    assert tuple(
        ip_address
        for request in requests
        for ip_address in request.ip_addresses
    ) == ip_addresses
    assert all(
        len(request.qualys_ips_value.encode("ascii")) <= MAX_IGNORE_IPS_LENGTH
        for request in requests
    )
    captured = capsys.readouterr()
    assert "Qualys API requests required: 2" in captured.out
    assert "Qualys responses: 2 successful batches" in captured.out
    assert "Total asset IPs confirmed ignored: 59" in captured.out
    assert "batch 1/2" in captured.err
    assert "batch 2/2" in captured.err


def test_cli_stops_after_unconfirmed_ignore_batch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ip_addresses = tuple(f"10.0.0.{value}" for value in range(1, 60))
    listing = QidVulnerabilityListing(
        vulnerabilities=tuple(
            QidVulnerabilityRecord(
                asset_id=f"asset-{index}",
                ip_address=ip_address,
                dns_hostname=None,
                qid=12345,
                status="Active",
                vulnerability_id=str(index),
            )
            for index, ip_address in enumerate(ip_addresses, start=1)
        )
    )
    calls = 0

    class FakeClient:
        def get_vulnerabilities_for_qid(self, qid, *, ip_filter):
            return listing

        def ignore_vulnerabilities(self, request):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise QualysClientError("simulated unconfirmed response")
            return IgnoreVulnerabilityResult(
                message="success",
                ignored=(),
            )

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "IGNORE QID 12345")

    result = cli.main(
        [
            "12345",
            "--ips",
            "10.0.0.1-10.0.0.59",
            "--ignore",
            "--comment",
            "Approved exception CHG001234",
        ]
    )

    assert result == 1
    assert calls == 2
    error = capsys.readouterr().err
    assert "Completed batches: 1/2" in error
    assert "Verify Qualys before retrying" in error


def test_cli_does_not_prompt_or_write_when_no_detections_match(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        NO_HOSTS_XML,
        requested_qid=12345,
    )

    class FakeClient:
        def get_vulnerabilities_for_qid(self, qid, *, ip_filter):
            return listing

        def ignore_vulnerabilities(self, request):
            raise AssertionError("ignore request must not be sent")

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )

    result = cli.main(
        [
            "12345",
            "--ips",
            "192.0.2.10",
            "--ignore",
            "--comment",
            "Approved exception CHG001234",
        ]
    )

    assert result == 0
    assert "No ignore request sent" in capsys.readouterr().out


def test_cli_rejects_verify_ignored_with_ignore_before_loading_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli.AppConfig,
        "load",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not load config")),
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "12345",
                "--ips",
                "192.0.2.10",
                "--verify-ignored",
                "--ignore",
                "--comment",
                "approved",
            ]
        )

    assert exc_info.value.code == 2
    assert "may not be combined with --ignore" in capsys.readouterr().err


def test_cli_verification_is_read_only_and_prints_evidence_backed_totals(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        VERIFICATION_XML,
        requested_qid=12345,
    )
    calls: list[tuple[int, IpFilter, bool]] = []

    class FakeClient:
        def get_vulnerabilities_for_qid(
            self, qid, *, ip_filter, include_ignored=False
        ):
            calls.append((qid, ip_filter, include_ignored))
            return listing

        def ignore_vulnerabilities(self, request):
            raise AssertionError("verification must never call the ignore endpoint")

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )

    result = cli.main(
        [
            "12345",
            "--ips",
            "192.0.2.10-192.0.2.13, 192.0.2.99",
            "--verify-ignored",
        ]
    )

    assert result == 0
    assert calls[0][0] == 12345
    assert calls[0][1].qualys_value == "192.0.2.10-192.0.2.13,192.0.2.99"
    assert calls[0][2] is True
    output = capsys.readouterr().out
    assert "Ignored State" in output
    assert "ignored" in output
    assert "not ignored" in output
    assert "unknown" in output
    assert "Assets matched with no returned detection for QID 12345" in output
    assert "asset-without-qid | 192.0.2.13" in output
    assert "192.0.2.99: no asset/detection returned" in output
    assert "Total IP addresses or ranges requested: 2" in output
    assert "Total assets matched: 4" in output
    assert "Total assets with the QID: 3" in output
    assert "Total assets confirmed ignored: 1" in output
    assert "Total assets not ignored: 1" in output
    assert "Total assets with unknown ignore state: 1" in output
    assert "Total vulnerability detections returned: 5" in output
    assert "cannot verify the stored exception comment" in output


def test_cli_verification_keeps_no_matching_asset_limitation_visible(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = QidVulnerabilityListing.from_api_xml(
        NO_HOSTS_XML,
        requested_qid=12345,
    )

    class FakeClient:
        def get_vulnerabilities_for_qid(
            self, qid, *, ip_filter, include_ignored=False
        ):
            assert include_ignored is True
            return listing

        def ignore_vulnerabilities(self, request):
            raise AssertionError("verification must never call the ignore endpoint")

    monkeypatch.setattr(cli.AppConfig, "load", lambda **kwargs: object())
    monkeypatch.setattr(
        cli.QidVulnerabilityClient,
        "from_config",
        lambda config: FakeClient(),
    )

    assert cli.main(
        ["12345", "--ips", "192.0.2.99", "--verify-ignored"]
    ) == 0

    output = capsys.readouterr().out
    assert "No asset or QID detection was returned" in output
    assert "cannot distinguish an unmatched asset" in output
    assert "Total assets matched: 0" in output
    assert "Total vulnerability detections returned: 0" in output


@pytest.mark.parametrize(
    ("raw_value", "expected_error"),
    [
        ("192.168.0.999", "invalid IPv4 address"),
        ("192.168.0.92-192.168.0.87", "ending address lower"),
        ("192.168.0.1-", "incomplete IPv4 range"),
        ("", "IP filter must not be empty"),
        ("192.168.0.1,,192.168.0.2", "entry 2 must not be empty"),
    ],
)
def test_cli_rejects_invalid_ip_filter_before_loading_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    raw_value: str,
    expected_error: str,
) -> None:
    config_loaded = False

    def fake_load(**kwargs):
        nonlocal config_loaded
        config_loaded = True

    monkeypatch.setattr(cli.AppConfig, "load", fake_load)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["12345", "--ips", raw_value])

    assert exc_info.value.code == 2
    assert not config_loaded
    error = capsys.readouterr().err
    assert expected_error in error
    assert "Traceback" not in error
