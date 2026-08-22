import re

def read_log(filename):
    with open(filename,'r') as f:
       lines=f.readlines()
    return lines
class LogEntry:
    def __init__(self,ip,timestamp,username,status):
        self.ip=ip
        self.timestamp=timestamp
        self.username=username
        self.status=status
    def is_failed(self):
        return self.status=='failed'
    def __repr__(self):
        return f"{self.timestamp}|{self.ip}|{self.username}|{self.status}"


def parse_line(line):
    pattern_failed = r'(\w+ \d+ [\d:]+).*sshd\[\d+\]: Failed password for (invalid user )?(\w+) from ([\d.]+)'
    match = re.search(pattern_failed, line)
    if match:
        return LogEntry(ip=match.group(4),timestamp=match.group(1),username=match.group(3),status='failed')
    pattern_success = r'(\w+ \\d+ [\d:]+).*sshd\[\d+\]: Accepted password for (\w+) from ([\d.]+)'
    match = re.search(pattern_success, line)
    if match:
        return LogEntry(ip=match.group(3),timestamp=match.group(1),username=match.group(2),status='accepted')
    return None

def parse_log(filepath):
    lines=read_log(filepath)
    print(f'lines read:',len(lines))
    entries=[]
    for line in lines:
        result=parse_line(line)
        print('trying lines:',line[:30])
        print('result:',result)
        if result is not None:
            entries.append(result)
    return entries
if __name__=='__main__':
    entries=parse_log('sample_logs/auth.log')
    for entry in entries:
        print(entry)

