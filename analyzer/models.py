"""Data models used across the analyzer."""


class LogEntry:
    """Represents a single parsed SSH auth log line."""

    def __init__(self, ip, timestamp, username, status):
        self.ip = ip
        self.timestamp = timestamp
        self.username = username
        self.status = status

    def is_failed(self):
        return self.status == 'failed'

    def __repr__(self):
        return f"{self.timestamp}|{self.ip}|{self.username}|{self.status}"
