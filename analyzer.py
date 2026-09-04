import re
import collections
from datetime import datetime,timedelta
import os,json
import requests
from tabulate import tabulate
import argparse,csv
from dotenv import load_dotenv

load_dotenv()

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
    pattern_success = r'(\w+ \d+ [\d:]+).*sshd\[\d+\]: Accepted password for (\w+) from ([\d.]+)'
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
            for index in range(len(attempts) - 1):
                first_time=datetime.strptime("2024 " + attempts[index].timestamp, "%Y %b %d %H:%M:%S")              
                second_time=datetime.strptime("2024 " + attempts[index+1].timestamp, "%Y %b %d %H:%M:%S")               
                time_difference=second_time-first_time
                if time_difference<=timedelta(minutes = 10):
                    flagged.append({'ip':ip , 'count':len(attempts),'reason':'Bruteforce'})
                    break
    return flagged

#           LOAD CACHE FUNCTION

def load_cache(filename='cache.json'):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

 #          SAVING CACHE  
 #  
def save_cache(cache, filename='cache.json'):
    with open(filename,'w') as f:
        json.dump(cache,f)

#       CHECKAPI FUNCTION

def check_ip(ip, api_key):
    cache=load_cache()
    if ip in cache:
        return cache[ip]
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    param={'ipAddress':ip,'maxAgeInDays':90}
    try:
        response = requests.get(url, headers=headers, params=param, timeout=10)
        response.raise_for_status()
        data = response.json()['data']
        result = {
            'ip': ip,
            'abuse_score': data['abuseConfidenceScore'],
            'country': data.get('countryCode'),
            'isp': data.get('isp')
        }
        cache[ip] = result
        save_cache(cache)
        return result
    except requests.exceptions.RequestException as e:
        return {'ip': ip, 'error': str(e)}
#           EXPORT CSV

def export_csv(results,filename):
    fieldnames=['ip','abuse_score','country','isp']
    with open(filename,'w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fieldnames,extrasaction='ignore')
        writer.writeheader()
        writer.writerows (results)

#           PRINTING  TABLE

def print_table(results):
    print(tabulate(results, headers='keys'))


#           MAIN CALL

def main():
    parser=argparse.ArgumentParser(description='Log Analyzer')
    parser.add_argument('--file', required=True, help='Path to log file')
    parser.add_argument('--threshold', type=int, default=5, help='Failed attempts threshold') 
    args=parser.parse_args()
    entries=parse_log(args.file)
    grouped=group_by_ip(entries)
    flagged_list=detect_bruteforce(grouped,args.threshold)
    for item in flagged_list:
        print(f"Alert:{item['ip']} had {item['count']} failed attempts due to {item['reason']}.")
    my_key = os.environ.get('ABUSEIPDB_KEY')
    enriched = [check_ip(f['ip'], my_key) for f in flagged_list]
    print_table(enriched)
    export_csv(enriched,'report.csv')

'''
if __name__=='__main__':
    entries=parse_log('sample_logs/auth.log')
    grouped=group_by_ip(entries)
    flagged_list=detect_bruteforce(grouped)
    for item in flagged_list:
        print(f"Alert:{item['ip']} had {item['count']} failed attempts due to {item['reason']}.")
    my_key = os.environ.get('ABUSEIPDB_KEY')
    enriched = [check_ip(f['ip'], my_key) for f in flagged_list]
    for e in enriched:
        print(e)'''
if __name__=='__main__':
    main()
  