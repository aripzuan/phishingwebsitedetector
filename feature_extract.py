"""
Shared feature extraction module.
"""

import math
import ipaddress
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_reader", "utm_name",
    "uid", "uuid", "ref", "fbclid", "gclid", "msclkid",
    "mc_cid", "mc_eid", "_hsenc", "_hsmi", "hs_email_action",
    "ncid", "igshid", "s_cid",
}

PHISHING_KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "signin"]
SHORTENERS        = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
SKETCHY_TLDS      = {".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz", ".club"}

FREE_DDNS = [
    "servebbs.org",
    "servebbs.com",
    "servebbs.net",
    "no-ip.org",
    "no-ip.biz",
    "no-ip.com",
    "ddns.net",
    "dyndns.org",
    "dyndns.com",
    "dyndns.net",
    "hopto.org",
    "myftp.biz",
    "myftp.org",
    "myvnc.com",
    "redirectme.net",
    "serveftp.com",
    "servegame.com",
    "servehalflife.com",
    "servehttp.com",
    "serveirc.com",
    "serveminecraft.net",
    "servemp3.com",
    "servepics.com",
    "servequake.com",
    "sytes.net",
    "viewdns.net",
    "zapto.org",
    "changeip.com",
    "dnsdynamic.org",
    "dynu.com",
    "afraid.org",
    "chickenkiller.com",
    "crabdance.com",
    "ignorelist.com",
    "jumpingcrab.com",
    "moo.com",
    "picdns.com",
    "strangled.net",
]

BRANDS = ["paypal", "google", "facebook", "apple", "bank"]

FEATURE_NAMES = [
    "suspicious_words", "dots", "hyphens", "path_len", "domain_digits",
    "domain_len", "domain_entropy", "num_params", "is_shortened", "has_ip",
    "has_at", "url_length", "subdomains", "https", "prefix_suffix",
    "redirect", "abnormal_www", "double_slash", "special_chars",
    "suspicious_tld", "brand", "free_ddns",
]


def entropy_of(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def strip_tracking_params(url: str) -> str:
    parsed    = urlparse(url)
    params    = parse_qs(parsed.query, keep_blank_values=True)
    clean     = {k: v for k, v in params.items() if k.lower() not in TRACKING_PARAMS}
    new_query = urlencode(clean, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def path_is_encoded(path: str) -> bool:
    return (
        len(path) > 50
        and bool(re.match(r'^[/A-Za-z0-9_\-+.]+$', path))
        and not re.search(r'/[a-z]{3,}-[a-z]{3,}', path)
    )


def extract_features(raw_url: str) -> list:
    url    = strip_tracking_params(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path   = parsed.path
    url_l  = url.lower()

    domain_entropy     = entropy_of(domain)
    encoded_path       = path_is_encoded(path)
    effective_path_len = min(len(path), 60) if encoded_path else len(path)
    redirect           = int(url.rfind("//") > 6)

    try:
        ipaddress.ip_address(domain.split(":")[0])
        has_ip = 1
    except ValueError:
        has_ip = 0

    is_free_ddns = int(any(ddns in domain for ddns in FREE_DDNS))

    return [
        int(any(kw in url_l for kw in PHISHING_KEYWORDS)),
        url.count("."),
        url.count("-"),
        effective_path_len,
        sum(c.isdigit() for c in domain),
        len(domain),
        domain_entropy,
        url.count("="),
        int(any(s in url for s in SHORTENERS)),
        has_ip,
        int("@" in url),
        len(url),
        domain.count("."),
        int(parsed.scheme == "https"),
        int("-" in domain),
        redirect,
        int("www." in path),
        redirect,
        sum(1 for c in url if c in "@?-.=#%+$"),
        int(any(tld in domain for tld in SKETCHY_TLDS)),
        int(any(b in url_l for b in BRANDS)),
        is_free_ddns,
    ]
