import re
import collections

#               READ LOG FILE

def read_log(filename):
    with open(filename,'r') as f:
       lines=f.readlines()
    return lines

#               LOG ENTERY CLASS

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
    
#           PARSELINE FUNCTION

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

#            PARSELOG FUNCTION

def parse_log(filepath):
    lines=read_log(filepath)
    entries=[]
    for line in lines:
        result=parse_line(line)
        if result is not None:
            entries.append(result)
    return entries

#               GROUPING IPS

def group_by_ip(entries):
    grouped=collections.defaultdict(list)
    for entry in entries:
        if entry.is_failed():
            grouped[entry.ip].append(entry)
    return grouped

#               DETECTION LOGIC

def detect_bruteforce(grouped,threshold=5):
    flagged=[]
    for ip,attempts in grouped.items():
        if len(attempts)>=threshold:
            flagged.append({'ip':ip , 'count':len(attempts)})
    return flagged

#           MAIN CALL

if __name__=='__main__':
    entries=parse_log('sample_logs/auth.log')
    grouped=group_by_ip(entries)
    flagged_list=detect_bruteforce(grouped)
    for item in flagged_list:
        print(f"Alert:{item['ip']} had {item['count']} failed attempts.")
    

