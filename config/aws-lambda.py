import boto3
import os
import re
import requests
from urllib.parse import urlparse
import tldextract

def domain_in_ioc(domain):
    ext = tldextract.extract(domain.lower())
    if not ext.domain or not ext.suffix:
        return False

    # Construct base domain
    base_domain = f"{ext.domain}.{ext.suffix}"

    # Check base domain
    if base_domain in ioc_domains:
        return True

    # if subdomain: check that aswell
    if ext.subdomain:
        full_domain = f"{ext.subdomain}.{base_domain}"
        if full_domain in ioc_domains:
            return True
    return False

s3 = boto3.client('s3')

DISCORD_WEBHOOK_URL = "XXXXXXXXXXXXXXXXXXXXXX"
IOC_FEEDS = [
    # Domains (127.0.0.1 <DOMAIN>)
    "https://urlhaus.abuse.ch/downloads/hostfile/", # Payload delivery & C2 Botnets
    "https://threatfox.abuse.ch/downloads/hostfile/", # Payload delivery & C2 Botnets
    
    # IPs
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", # C2 Botnets & IoC
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt", # Level 4
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt", # Level 5
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt", # Level 6
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt", # Level 7
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt", # Level 8
    
]

ioc_domains = set()
ioc_ips = set()
ext = tldextract.TLDExtract(cache_dir="/tmp/tld_cache")  # tldextract cachefolder

# IPv4 Regex: keine CIDR, nur einzelne IPs 
ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def load_ioc_feeds():
    ioc_domains.clear()
    ioc_ips.clear()

    for feed in IOC_FEEDS:
        try:
            resp = requests.get(feed, timeout=10)
            resp.raise_for_status()
            lines = resp.text.splitlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                # Domains: urlhaus.abuse.ch + threatfox.abuse.ch
                if "urlhaus.abuse.ch" in feed or "threatfox.abuse.ch" in feed:
                    # Hostfile: "127.0.0.1<TAB>domain.xyz"
                        if line.startswith("127.0.0.1"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ioc_domains.add(parts[1].lower())

                # IPs: feodotracker.abuse.ch + Github/Ipsum
                elif "feodotracker.abuse.ch" in feed or "raw.githubusercontent.com" in feed:
                    ip_part = line.split()[0]  # Ignore number of blacklists

                    if ipv4_pattern.match(ip_part):
                        if all(0 <= int(octet) <= 255 for octet in ip_part.split(".")):
                            ioc_ips.add(ip_part)

        except Exception as e:
            print(f"Error loading IOC feed {feed}: {e}")

    print(f"Loaded {len(ioc_domains)} IOC domains and {len(ioc_ips)} IOC IPs")

# Log-Parser, IPs & Domains
def extract_domains_from_log(log_text):
    domain_pattern = re.compile(r"(?:forwarded|reply|query\[A\]) ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
    return set(match.group(1).lower() for match in domain_pattern.finditer(log_text))

# Subdomains (only TLDs)
def domain_in_ioc(domain):
    ext = tldextract.extract(domain.lower())
    if not ext.domain or not ext.suffix:
        return False

    base_domain = f"{ext.domain}.{ext.suffix}"

    if base_domain in ioc_domains:
        return True

    # if subdomain: check that aswell
    if ext.subdomain:
        full_domain = f"{ext.subdomain}.{base_domain}"
        if full_domain in ioc_domains:
            return True
    return False

def extract_ips_from_log(log_text):
    ip_pattern = re.compile(r"(?:cached[-\w]*|reply) .* is (\d{1,3}(?:\.\d{1,3}){3})")
    return set(match.group(1) for match in ip_pattern.finditer(log_text))

# Discord alerting
def send_discord_alert(matches, s3_key):
    content = f"**⚠ Threat DNS detected!**\nFile: `{s3_key}`\nMatches:\n" + "\n".join(matches)
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": content}, timeout=5)
        if response.status_code != 204:
            print(f"Discord alert failed with status {response.status_code}")
    except Exception as e:
        print(f"Error sending Discord alert: {e}")

# Getting bucket & file from s3, sending logs from lambda, actual matching mechanism
def lambda_handler(event, context):
    load_ioc_feeds()

    record = event['Records'][0]
    bucket = record['s3']['bucket']['name']
    key = record['s3']['object']['key']
    print(f"Processing s3://{bucket}/{key}")

    tmp_file = f"/tmp/{os.path.basename(key)}"
    s3.download_file(bucket, key, tmp_file)

    with open(tmp_file, "r", encoding="utf-8", errors="ignore") as f:
        log_text = f.read()

    domains_in_log = extract_domains_from_log(log_text)
    ips_in_log = extract_ips_from_log(log_text)

    matches = sorted(
        [d for d in domains_in_log if domain_in_ioc(d)] +
        [ip for ip in ips_in_log if ip in ioc_ips]
    )

    if matches:
        print(f"Found {len(matches)} IOC matches")
        send_discord_alert(matches, key)
    else:
        print("No IOC matches found")

    return {
        'statusCode': 200,
        'body': f'Processed {key}, found {len(matches)} IOC matches'
    }
