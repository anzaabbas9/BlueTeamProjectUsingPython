"""Groups log entries by IP and detects brute-force patterns."""

import collections
from datetime import datetime, timedelta


def group_by_ip(entries):
    """Group failed login entries by source IP."""
    grouped = collections.defaultdict(list)
    for entry in entries:
        if entry.is_failed():
            grouped[entry.ip].append(entry)
    return grouped


def detect_bruteforce(grouped, threshold=5, window_minutes=10):
    """Flag any IP with `threshold`+ failed attempts within `window_minutes`."""
    flagged = []
    for ip, attempts in grouped.items():
        if len(attempts) >= threshold:
            for index in range(len(attempts) - 1):
                first_time = datetime.strptime("2024 " + attempts[index].timestamp, "%Y %b %d %H:%M:%S")
                second_time = datetime.strptime("2024 " + attempts[index + 1].timestamp, "%Y %b %d %H:%M:%S")
                time_difference = second_time - first_time
                if time_difference <= timedelta(minutes=window_minutes):
                    flagged.append({'ip': ip, 'count': len(attempts), 'reason': 'Bruteforce'})
                    break
    return flagged
