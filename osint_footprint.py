#!/usr/bin/env python3
"""
OSINT Footprint Analyzer - CLI entry point.

Given a username, email, or domain, dumps whatever public footprint info
we can grab. This module just wires the CLI together - the actual recon
logic lives in the sibling modules it imports below (username.py,
domain.py, email_check.py, exif.py, correlation.py, risk.py, report.py,
utils.py).

Usage:
    python3 osint_footprint.py --username johndoe
    python3 osint_footprint.py --domain example.com
    python3 osint_footprint.py --email john@example.com
    python3 osint_footprint.py --username johndoe --domain example.com --email john@example.com --out results.json
"""

import argparse
import json
import os
import sys
from datetime import datetime

import correlation
import domain as domain_mod
import email_check
import exif as exif_mod
import report
import risk
import username as username_mod
import utils


def main():
    parser = argparse.ArgumentParser(description="OSINT Footprint Analyzer")
    parser.add_argument("--username", help="username to search across platforms")
    parser.add_argument("--domain", help="domain to recon")
    parser.add_argument("--email", help="email to check")
    parser.add_argument("--image", help="path to a local image file for EXIF metadata extraction")
    parser.add_argument("--hibp-key", help="HaveIBeenPwned API key for live breach checking "
                                            "(or set the HIBP_API_KEY environment variable instead, "
                                            "so the key never ends up typed into shell history or a script)")
    parser.add_argument("--out", help="save results to JSON file", default=None)
    parser.add_argument("--html", help="save a self-contained HTML report to this path", default=None)
    args = parser.parse_args()

    if not any([args.username, args.domain, args.email, args.image]):
        parser.print_help()
        sys.exit(1)

    # CLI flag takes precedence if both are set, but the env var is the
    # recommended path - it never ends up in shell history or a committed script
    hibp_api_key = args.hibp_key or os.environ.get("HIBP_API_KEY")

    report_data = {
        "generated_at": datetime.now().isoformat() + "Z",
        "target": {
            "username": args.username,
            "domain": args.domain,
            "email": args.email,
            "image": args.image,
        },
    }

    if args.username:
        report_data["username_results"] = username_mod.check_username(args.username)

    if args.domain:
        report_data["domain_results"] = domain_mod.check_domain(args.domain)

    if args.email:
        report_data["email_results"] = email_check.check_email(args.email, hibp_api_key=hibp_api_key)

    if args.image:
        report_data["exif_results"] = exif_mod.extract_exif(args.image)

    # correlation only ever compares username/domain/email against each
    # other, so with fewer than two of those supplied it can't find
    # anything by definition - skip it entirely (leaving "correlations"
    # unset) rather than reporting a foregone "no correlations found"
    # conclusion. report.generate_html_report() already treats a missing
    # "correlations" key as "the engine never ran" and hides the section.
    identifier_count = sum(1 for v in (args.username, args.domain, args.email) if v)
    if identifier_count >= 2:
        correlations = correlation.correlate_findings(report_data)
        report_data["correlations"] = correlations
        if correlations:
            print("\n[*] Identifier correlations found:")
            for c in correlations:
                print(f"    [{c['confidence']:6s}] {c['description']}")
        else:
            print("\n[*] No direct identifier correlations found.")

    dorks = utils.generate_dorks(args.username, args.domain, args.email)
    if dorks:
        print("\n[*] Suggested manual Google dorks:")
        for d in dorks:
            print(f"    {d}")
        report_data["suggested_dorks"] = dorks

    # risk score is computed last - it only reads what's already in
    # `report_data`, so it naturally reflects whichever checks actually ran
    risk_result = risk.calculate_risk(report_data)
    report_data["risk_score"] = risk_result
    print(f"\n[*] Exposure risk score: {risk_result['score']}/{risk_result['max_score']} ({risk_result['severity']})")
    if risk_result["triggered_rules"]:
        for t in risk_result["triggered_rules"]:
            print(f"    +{t['points']:<3} {t['description']}")
    else:
        print("    No risk factors triggered.")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.out}")

    if args.html:
        with open(args.html, "w") as f:
            f.write(report.generate_html_report(report_data))
        print(f"[+] HTML report saved to {args.html}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
