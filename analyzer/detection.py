import collections,requests
from datetime import datetime,timedelta

def group_by_ip(entries):
    """Group failed login entries by source IP."""
    grouped = collections.defaultdict(list)
    for entry in entries:
        if entry.is_failed():
            grouped[entry.ip].append(entry)
    return grouped


def _parse_timestamp(timestamp):
    """Parse a syslog-style timestamp, using a fixed placeholder year."""
    return datetime.strptime("2024 " + timestamp, "%Y %b %d %H:%M:%S")


def detect_bruteforce(grouped, threshold=5, window_minutes=10):
    """Flag any IP with `threshold`+ failed attempts clustered inside a
    single `window_minutes`-wide window."""
    flagged = []
    for ip, attempts in grouped.items():
        attempts = sorted(attempts, key=lambda a: _parse_timestamp(a.timestamp))
        for index in range(len(attempts) - threshold + 1):
            window_start = _parse_timestamp(attempts[index].timestamp)
            window_end = _parse_timestamp(attempts[index + threshold - 1].timestamp)
            if window_end - window_start <= timedelta(minutes=window_minutes):
                flagged.append({'ip': ip, 'count': len(attempts), 'reason': 'Bruteforce'})
                break
    return flagged