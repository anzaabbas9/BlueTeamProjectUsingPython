"""CSV export and colored terminal reporting via `rich`."""

import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

CSV_FIELDNAMES = ['ip', 'abuse_score', 'country', 'isp']


def export_csv(results, filename='report.csv'):
    """Write enrichment results to a CSV file. Silently drops unexpected fields."""
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)


def score_style(score):
    """Return a rich color style based on abuse confidence score severity."""
    if score >= 80:
        return "bold red"
    elif score >= 30:
        return "bold yellow"
    return "bold green"


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]Blue Team Log Analyzer[/bold cyan]\n"
        "[dim]Brute-force Detection + Threat Intel Enrichment[/dim]",
        border_style="cyan"
    ))


def print_alerts(flagged_list):
    if not flagged_list:
        console.print("[bold green]No brute-force activity detected.[/bold green]")
        return
    for item in flagged_list:
        console.print(
            f"[bold red]ALERT[/bold red] :warning: [white]{item['ip']}[/white] had "
            f"[bold]{item['count']}[/bold] failed attempts — reason: [italic]{item['reason']}[/italic]"
        )


def print_table(results):
    table = Table(title="Threat Intel Enrichment Results", header_style="bold cyan", border_style="grey50")
    table.add_column("IP Address", style="white", no_wrap=True)
    table.add_column("Abuse Score", justify="right")
    table.add_column("Country", justify="center")
    table.add_column("ISP", style="dim")

    for r in results:
        if 'error' in r:
            table.add_row(r.get('ip', '-'), "[red]ERROR[/red]", "-", r.get('error', 'Unknown error'))
            continue
        score = r.get('abuse_score', 0)
        style = score_style(score)
        table.add_row(
            r['ip'],
            f"[{style}]{score}[/{style}]",
            r.get('country') or "-",
            r.get('isp') or "-"
        )
    console.print(table)
