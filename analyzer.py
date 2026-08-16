import re

def read_log(filename):
    with open(filename,'r') as f:
       lines=f.readlines()
    return lines
def parse_line(line):
    pattern_failed = r'Failed password for (invalid user )?(\w+) from ([\d.]+)'
    match = re.search(pattern_failed, line)
    if match:
        return {
            'user': match.group(2),
            'ip': match.group(3),
            'status': 'failed'
        }
    
    pattern_success = r'Accepted password for (\w+) from ([\d.]+)'
    match = re.search(pattern_success, line)
    if match:
        return {
            'user': match.group(1),       
            'ip': match.group(2),        
            'status': 'accepted'       
        }
    
    return None

def parse_log(filepath):
    lines=read_log(filepath)
    entries=[]
    for line in lines:
        result=parse_line(line)
        if result is not None:
            entries.append(result)
    return entries
if __name__=='__main__':
    entries=parse_log('sample_logs/auth.log')
    for e in entries:
        print(e)




