"""Reads raw log files and parses lines into LogEntry objects."""

import re
from analyzer.models import LogEntry

PATTERN_FAILED = r'(\w+ \d+ [\d:]+).*sshd\[\d+\]: Failed password for (invalid user )?(\w+) from ([\d.]+)'
PATTERN_SUCCESS = r'(\w+ \d+ [\d:]+).*sshd\[\d+\]: Accepted password for (\w+) from ([\d.]+)'


def read_log(filename):
    """Read a log file and return a list of raw lines."""
    with open(filename, 'r') as f:
        lines = f.readlines()
    return lines


def parse_line(line):
    """Parse a single log line into a LogEntry, or None if it doesn't match."""
    match = re.search(PATTERN_FAILED, line)
    if match:
        return LogEntry(ip=match.group(4), timestamp=match.group(1),
                         username=match.group(3), status='failed')

    match = re.search(PATTERN_SUCCESS, line)
    if match:
        return LogEntry(ip=match.group(3), timestamp=match.group(1),
                         username=match.group(2), status='accepted')

    return None


def parse_log(filepath):
    """Read and parse a full log file into a list of LogEntry objects."""
    lines = read_log(filepath)
    entries = []
    for line in lines:
        result = parse_line(line)
        if result is not None:
            entries.append(result)
    return entries
