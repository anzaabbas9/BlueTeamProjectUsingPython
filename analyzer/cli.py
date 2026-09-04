"""Command-line interface — ties parsing, detection, enrichment, and reporting together."""

import argparse
import os
from dotenv import load_dotenv

from analyzer.log_parser import parse_log
from analyzer.detection import group_by_ip, detect_bruteforce
from analyzer.threat_intel import check_ip
from analyzer.reporting import print_banner, print_alerts, print_table, export_csv, console

load_dotenv()


def build_parser():
    parser = argparse.ArgumentParser(
        prog='analyzer',
        description='Blue Team Log Analyzer + Threat Intel Enrichment Tool'
    )
    parser.add_argument('--file', required=True, help='Path to the log file to analyze')
    parser.add_argument('--threshold', type=int, default=5, help='Failed-attempt threshold to flag as brute-force')
    parser.add_argument('--output', default='report.csv', help='Path to write the CSV report (default: report.csv)')
    return parser


def main():
    args = build_parser().parse_args()

    print_banner()

    entries = parse_log(args.file)
    grouped = group_by_ip(entries)
    flagged_list = detect_bruteforce(grouped, args.threshold)
    print_alerts(flagged_list)

    api_key = os.environ.get('ABUSEIPDB_KEY')
    enriched = [check_ip(f['ip'], api_key) for f in flagged_list]

    if enriched:
        print_table(enriched)
        export_csv(enriched, args.output)
        console.print(f"[dim]Report saved to {args.output}[/dim]")


if __name__ == '__main__':
    main()
