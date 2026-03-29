import requests
import whois
import tldextract
import validators
from urllib.parse import urlparse, parse_qs
from datetime import datetime

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "password", "confirm"
]

SUSPICIOUS_PARAMS = [
    "redirect", "token", "session",
    "next", "continue"
]


def analyze_url(url):
    report = {
        "valid": False,
        "risk_score": 0,
        "domain_age": None,
        "redirects": 0,
        "suspicious_keywords": [],
        "suspicious_params": [],
        "uses_ip": False
    }

    # Validate URL
    if not validators.url(url):
        return report

    report["valid"] = True
    risk = 0

    parsed = urlparse(url)

    # check IP address
    if parsed.hostname and parsed.hostname.replace(".", "").isdigit():
        report["uses_ip"] = True
        risk += 15

    # suspicious keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            report["suspicious_keywords"].append(word)
            risk += 5

    # suspicious parameters
    params = parse_qs(parsed.query)
    for param in params:
        if param.lower() in SUSPICIOUS_PARAMS:
            report["suspicious_params"].append(param)
            risk += 10

    # redirects check
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        report["redirects"] = len(r.history)
        risk += len(r.history) * 5
    except:
        pass

    # domain age
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"

        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days
        report["domain_age"] = age_days

        if age_days < 7:
            risk += 30
        elif age_days < 30:
            risk += 15

    except:
        report["domain_age"] = "Unknown"

    report["risk_score"] = min(risk, 100)

    return report