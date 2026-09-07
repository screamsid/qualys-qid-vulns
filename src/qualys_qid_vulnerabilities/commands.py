"""Application workflows behind the command-line interface."""

from __future__ import annotations

from collections.abc import Callable
import logging
import sys

from .asset_search import AssetSearch
from .client import QidVulnerabilityClient
from .config import AppConfig
from .errors import ConfigurationError, QualysClientError
from .ignore import IgnoreRequestError, IgnoreVulnerabilityRequest, create_ignore_request_batches
from .ip_filter import IpFilter
from .models import IgnoreVulnerabilityResult
from .output import format_table, print_verification, safe_output
from .progress import ProgressDisplay

LOGGER = logging.getLogger("qualys_qid_vulnerabilities.cli")


def run(args, *, parser, config_loader: Callable = AppConfig.load,
        client_factory: Callable = QidVulnerabilityClient.from_config,
        confirmation: Callable | None = None) -> int:
    """Run lookup, verification, and the guarded ignore workflow."""
    mode = "verify-ignored" if args.verify_ignored else "ignore" if args.ignore else "lookup"
    LOGGER.info("BEGIN COMMAND | qid=%s | mode=%s", args.qid, mode)
    progress = ProgressDisplay(interactive=None if not args.verbose else False)
    try:
        with progress.step("Loading and validating runtime configuration"):
            config = config_loader(config_file=args.config_file, env_file=args.env_file)
            client = client_factory(config)
        lookup_filter = args.ips
        if args.asset_search is not None:
            with progress.step("Searching Qualys Host List for selected assets"):
                matched_assets = client.search_assets(args.asset_search)
            resolved_ips = tuple(asset.ip_address for asset in matched_assets if asset.ip_address)
            if not resolved_ips:
                print("No matching assets with an IP address were returned by Qualys.")
                return 0
            lookup_filter = IpFilter.parse(",".join(resolved_ips))
        description = (f"Verifying ignored state for QID {args.qid} in Qualys" if args.verify_ignored else f"Querying Qualys for QID {args.qid} detections" if args.qid is not None else "Querying Qualys for all QID detections")
        with progress.step(description):
            if args.verify_ignored:
                listing = client.get_vulnerabilities_for_qid(
                    args.qid, ip_filter=lookup_filter, include_ignored=True
                )
            else:
                listing = client.get_vulnerabilities_for_qid(
                    args.qid, ip_filter=lookup_filter
                )
            if args.ignored_only:
                listing = listing.ignored_only()
    except (ConfigurationError, QualysClientError) as exc:
        LOGGER.error("QID command failed: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        LOGGER.warning("COMMAND INTERRUPTED | qid=%s | mode=%s | no Qualys changes were made", args.qid, mode)
        print("Interrupted; no Qualys changes were made.", file=sys.stderr)
        return 130

    if args.verify_ignored:
        print_verification(args.qid, lookup_filter, listing)
        return 0
    all_assets = lookup_filter is None
    selector_label = "all assets" if all_assets else "asset selector" if args.asset_search is not None else "IP filter"
    qid_label = f"QID {args.qid}" if args.qid is not None else "QIDs"
    if listing.matched_asset_count == 0:
        print(f"No assets with {qid_label} detections were returned." if all_assets else f"No assets matched the supplied {selector_label}.")
    elif not listing.vulnerabilities:
        print(f"Assets matched the supplied {selector_label}, but {qid_label} was not found.")
    else:
        print("Matching vulnerability detections were found.")
    print(); print(format_table(listing)); print()
    print(f"Total IPs or ranges requested: {lookup_filter.requested_count}" if lookup_filter is not None else "Total scope: all assets returned by Qualys")
    print(f"Total assets matched: {listing.matched_asset_count}")
    print(f"Total assets affected: {listing.affected_asset_count}")
    print(f"Total vulnerabilities found: {len(listing.vulnerabilities)}")
    if not args.ignore:
        return 0
    if not listing.vulnerabilities:
        print(); print("No ignore request sent because no matching detections were found.")
        return 0
    try:
        if lookup_filter is not None:
            unexpected_ips = sorted({record.ip_address for record in listing.vulnerabilities if not _ip_in_filter(lookup_filter, record.ip_address)})
            if unexpected_ips:
                raise IgnoreRequestError("Qualys returned vulnerability IPs outside the requested scope: " + ", ".join(unexpected_ips))
        requests = create_ignore_request_batches(qid=args.qid, ip_addresses=tuple(record.ip_address for record in listing.vulnerabilities), comments=args.comment, reopen_ignored_days=args.reopen_after_days)
    except IgnoreRequestError as exc:
        LOGGER.error("Could not prepare ignore request: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not (confirmation or confirm_ignore)(requests):
        print("Ignore cancelled; no Qualys changes were made.", file=sys.stderr)
        return 1
    results: list[IgnoreVulnerabilityResult] = []
    for number, request in enumerate(requests, start=1):
        try:
            detail = f" batch {number}/{len(requests)}" if len(requests) > 1 else ""
            with progress.step(f"Submitting confirmed ignore{detail} for QID {args.qid} to Qualys"):
                results.append(client.ignore_vulnerabilities(request))
        except QualysClientError as exc:
            LOGGER.error("Ignore request failed after %d successful batch(es): %s", len(results), exc)
            print(f"Error: Ignore outcome is unconfirmed and may have been partially applied. Verify Qualys before retrying. Completed batches: {len(results)}/{len(requests)}. {exc}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            LOGGER.warning("COMMAND INTERRUPTED | qid=%s | mode=ignore | ignore outcome is unconfirmed; verify Qualys before retrying", args.qid)
            print("Interrupted; ignore outcome is unconfirmed. Verify Qualys before retrying.", file=sys.stderr)
            return 130
    print()
    print(f"Qualys response: {safe_output(results[0].message)}" if len(results) == 1 else f"Qualys responses: {len(results)} successful batches")
    print(f"Total asset IPs confirmed ignored: {sum(result.affected_ip_count for result in results)}")
    print(f"Total ignore records returned: {sum(len(result.ignored) for result in results)}")
    return 0


def confirm_ignore(requests: tuple[IgnoreVulnerabilityRequest, ...]) -> bool:
    confirmation = f"IGNORE QID {requests[0].qid}"
    target_count = sum(len(request.ip_addresses) for request in requests)
    print(); print("WARNING: This will change Qualys and may close or create remediation tickets.")
    print(f"The write is limited to {target_count} exact matched asset IP address(es).")
    print(f"Qualys API requests required: {len(requests)} (each limited to 512 characters of exact IPs).")
    if requests[0].reopen_ignored_days is None:
        print("Automatic reopen: not set (ignore remains until restored).")
    else:
        print(f"Automatic reopen: {requests[0].reopen_ignored_days} day(s) after the ignore.")
    try:
        response = input(f"Type {confirmation!r} to continue: ")
    except KeyboardInterrupt:
        LOGGER.warning("COMMAND INTERRUPTED | qid=%s | mode=ignore | confirmation cancelled; no Qualys changes were made", requests[0].qid)
        return False
    except EOFError:
        return False
    return response == confirmation


def _ip_in_filter(ip_filter: IpFilter, ip_address: str) -> bool:
    try:
        return any(ip_filter.entry_matches(entry, ip_address) for entry in ip_filter.entries)
    except ValueError:
        return False
