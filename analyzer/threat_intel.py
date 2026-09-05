import time
import requests
from analyzer.cache import load_cache, save_cache

ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
REQUEST_DELAY_SECONDS = 1


def check_ip(ip, api_key):
    """
    Return threat intel for a given IP.
    Checks the local cache first; only calls AbuseIPDB on a cache miss.
    Errors are never cached, so a failed lookup will retry on the next run.
    """
    cache = load_cache()
    if ip in cache:
        return cache[ip]

    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
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
        time.sleep(REQUEST_DELAY_SECONDS)
        return result
    except requests.exceptions.RequestException as e:
        time.sleep(REQUEST_DELAY_SECONDS)
        return {'ip': ip, 'error': str(e)}