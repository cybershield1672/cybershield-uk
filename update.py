"""CyberShield UK: fetch public CISA Known Exploited Vulnerabilities feed.
Run with Python 3.10+: python update.py
No API key or external Python packages required.
"""
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
OUT = Path(__file__).with_name('threats.json')

def main():
    req = urllib.request.Request(URL, headers={'User-Agent': 'CyberShieldUK-ThreatFeed/1.0'})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = json.load(response)
    vulnerabilities = data.get('vulnerabilities')
    if not isinstance(vulnerabilities, list):
        raise ValueError('Unexpected CISA feed format')
    items = sorted(vulnerabilities, key=lambda x: x.get('dateAdded', ''), reverse=True)[:250]
    if not items or any(not x.get('cveID') for x in items):
        raise ValueError('Empty or invalid CISA feed; existing data preserved')
    payload = {'updated_at': datetime.now(timezone.utc).isoformat(), 'source': URL, 'items': [
        {'cve': x.get('cveID'), 'vendor': x.get('vendorProject'), 'product': x.get('product'),
         'name': x.get('vulnerabilityName'), 'date_added': x.get('dateAdded'),
         'action': x.get('requiredAction'), 'due_date': x.get('dueDate'),
         'notes': x.get('notes')} for x in items]}
    tmp = OUT.with_suffix('.tmp')
    tmp.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    tmp.replace(OUT)
    print(f"Saved {len(items)} known exploited vulnerabilities to {OUT}")

if __name__ == '__main__':
    main()
