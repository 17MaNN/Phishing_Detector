"""
feature_extractor.py

Returns features in the same order as your dataset (excluding index and Result).
If an external lookup (whois, DNS, traffic) is required, the function
tries local approximations and returns -1/0/1 values like your dataset.

You'll see a `meta` dict returned too so the UI can show intermediate info.
"""

import re
import socket
import requests
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup

# Optional imports for advanced lookups:
try:
    import whois
except Exception:
    whois = None

try:
    import dns.resolver
except Exception:
    dns = None

# List of URL shortening services (common ones)
SHORTENERS = set([
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly", "adf.ly",
    "bit.do", "mcaf.ee", "rebrand.ly", "is.gd", "cutt.ly"
])

# Names of features in dataset: (excluding 'index' and 'Result')
required_feature_names = [
 "having_IPhaving_IP_Address",
 "URLURL_Length",
 "Shortining_Service",
 "having_At_Symbol",
 "double_slash_redirecting",
 "Prefix_Suffix",
 "having_Sub_Domain",
 "SSLfinal_State",
 "Domain_registeration_length",
 "Favicon",
 "port",
 "HTTPS_token",
 "Request_URL",
 "URL_of_Anchor",
 "Links_in_tags",
 "SFH",
 "Submitting_to_email",
 "Abnormal_URL",
 "Redirect",
 "on_mouseover",
 "RightClick",
 "popUpWidnow",
 "Iframe",
 "age_of_domain",
 "DNSRecord",
 "web_traffic",
 "Page_Rank",
 "Google_Index",
 "Links_pointing_to_page",
 "Statistical_report"
]

def _to_label_bool(x):
    # Convert numeric/boolean into dataset labels -1,0,1
    # We'll return 1 for suspicious, -1 for legitimate (matching many phishing datasets),
    # and 0 for uncertain.
    if x is True:
        return 1
    if x is False:
        return -1
    return 0

def having_ip(url):
    # if URL contains an IP address instead of domain -> suspicious
    pattern = r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    return 1 if re.search(pattern, url) else -1

def url_length(url):
    L = len(url)
    if L < 54:
        return -1
    elif 54 <= L <= 75:
        return 0
    else:
        return 1

def shortening_service(url):
    domain = tldextract.extract(url).registered_domain
    if domain in SHORTENERS:
        return 1
    return -1

def having_at_symbol(url):
    return 1 if "@" in url else -1

def double_slash_redirecting(url):
    # count number of '//' occurrences beyond protocol
    idx = url.find("://")
    rest = url[idx+3:] if idx!=-1 else url
    return 1 if "//" in rest else -1

def prefix_suffix(url):
    # hyphen in domain suspicious
    domain = tldextract.extract(url).domain
    return 1 if "-" in domain else -1

def having_sub_domain(url):
    ext = tldextract.extract(url)
    sub = ext.subdomain
    if sub == "":
        return -1
    parts = sub.split(".")
    if len(parts) <= 1:
        return -1
    elif len(parts) == 2:
        return 0
    else:
        return 1

def ssl_final_state(url):
    # Simplified: if https -> good (-1). If not -> suspicious (1).
    try:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            return -1
        else:
            return 1
    except:
        return 0

def domain_registration_length(domain):
    # Requires whois; fallback to 0 (unknown)
    if whois is None:
        return 0
    try:
        w = whois.whois(domain)
        # Some whois libs return dict with 'expiration_date'
        exp = w.expiration_date
        creation = w.creation_date
        # handle list vs single
        if isinstance(exp, list):
            exp = exp[0]
        if isinstance(creation, list):
            creation = creation[0]
        if exp and creation:
            delta_days = (exp - creation).days
            if delta_days / 365 >= 5:
                return -1
            else:
                return 1
    except Exception:
        return 0
    return 0

def favicon_check(url, domain):
    # check whether favicon is served from same domain (approx)
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        icon = soup.find("link", rel=lambda r: r and "icon" in r.lower())
        if not icon:
            return -1  # no explicit favicon found -> likely legitimate in many datasets
        href = icon.get("href", "")
        if href.startswith("//"):
            href = "http:" + href
        if href.startswith("/") or domain in href:
            return -1
        else:
            return 1
    except Exception:
        return 0

def port_check(url):
    # check if URL uses non-standard port (suspicious)
    try:
        parsed = urlparse(url)
        port = parsed.port
        if port and port not in (80, 443):
            return 1
        return -1
    except:
        return 0

def https_token(url):
    # presence of 'https' token in domain part is suspicious
    parsed = tldextract.extract(url)
    domain_full = parsed.subdomain + "." + parsed.domain + "." + parsed.suffix if parsed.subdomain else parsed.domain + "." + parsed.suffix
    return 1 if "https" in domain_full.lower() else -1

def request_url(url, domain):
    # proportion of external resource links (img/script) compared to domain
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        tags = soup.find_all(["img", "script"])
        if not tags:
            return -1
        outside = 0
        for t in tags:
            src = t.get("src") or t.get("data-src") or ""
            if src and domain not in src and not src.startswith(("/", "#")):
                outside += 1
        ratio = outside / len(tags)
        if ratio < 0.22:
            return -1
        elif ratio <= 0.61:
            return 0
        else:
            return 1
    except Exception:
        return 0

def anchor_url(url, domain):
    # ratio of anchors linking outside or with javascript
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        anchors = soup.find_all("a")
        if not anchors:
            return -1
        suspicious = 0
        for a in anchors:
            href = a.get("href") or ""
            if href == "#" or href.lower().startswith("javascript") or (domain not in href and href.startswith("http")):
                suspicious += 1
        ratio = suspicious / len(anchors)
        if ratio < 0.31:
            return -1
        elif ratio <= 0.67:
            return 0
        else:
            return 1
    except Exception:
        return 0

def links_in_tags(url, domain):
    # count of suspicious tags (link, script, img) - reuse request_url logic
    return request_url(url, domain)

def sfh(url):
    # Server Form Handler: check form action attribute if empty/external
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return -1
        suspicious = 0
        for f in forms:
            action = f.get("action") or ""
            if action == "" or action == "about:blank" or (action.startswith("http")):
                suspicious += 1
        ratio = suspicious / len(forms)
        if ratio == 0:
            return -1
        elif ratio < 0.5:
            return 0
        else:
            return 1
    except Exception:
        return 0

def submitting_to_email(url):
    # forms with mailto in action suspicious
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        for f in forms:
            action = (f.get("action") or "").lower()
            if action.startswith("mailto:"):
                return 1
        return -1
    except Exception:
        return 0

def abnormal_url(url, domain):
    # If domain not in WHOIS or mismatch with DNS (fallback false)
    return -1  # placeholder; requires deep checks

def redirect(url):
    # number of redirects during a GET request
    try:
        r = requests.get(url, timeout=5)
        hops = len(r.history)
        if hops <= 1:
            return -1
        elif hops == 2:
            return 0
        else:
            return 1
    except Exception:
        return 0

def on_mouseover(url):
    # check inline onmouseover javascript on anchors
    try:
        resp = requests.get(url, timeout=5)
        return 1 if "onmouseover" in resp.text.lower() else -1
    except Exception:
        return 0

def right_click(url):
    # pages that disable right click often suspicious
    try:
        resp = requests.get(url, timeout=5)
        txt = resp.text.lower()
        return 1 if ("event.button==2" in txt or "contextmenu" in txt or "rightclick" in txt) else -1
    except Exception:
        return 0

def popup_window(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "window.open" in r.text.lower() else -1
    except Exception:
        return 0

def iframe(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "<iframe" in r.text.lower() else -1
    except Exception:
        return 0

def age_of_domain(domain):
    # needs whois; fallback 0
    if whois is None:
        return 0
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            # simplistic: older than 1 year -> -1, else 1
            from datetime import datetime
            age_days = (datetime.now() - creation).days
            return -1 if age_days > 365 else 1
    except Exception:
        return 0
    return 0

def dns_record(domain):
    if dns is None:
        return 0
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return -1 if answers else 1
    except Exception:
        return 1

def web_traffic(domain):
    # requires external API (Alexa/SimilarWeb). Return 0 as unknown.
    return 0

def page_rank(domain):
    # PageRank isn't public anymore; return 0
    return 0

def google_index(domain):
    # searching google programmatically needs API; return 0 as unknown
    return 0

def links_pointing_to_page(domain):
    # requires search engine/backlink API; return 0
    return 0

def statistical_report(domain):
    # if domain appears in known phishing blacklists (not implemented) -> 1 else -1
    return 0

def extract_features_from_url(url):
    """
    Returns (features_list, meta_dict)
    features_list order matches required_feature_names
    """
    meta = {}
    # normalize url
    if not url.startswith("http"):
        url = "http://" + url  # default scheme if missing

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ".".join(p for p in [ext.domain, ext.suffix] if p)

    meta['domain'] = domain

    features = []
    # 1 having_IP
    features.append(having_ip(url))
    # 2 URL length
    features.append(url_length(url))
    # 3 Shortining Service
    features.append(shortening_service(url))
    # 4 having_At_Symbol
    features.append(having_at_symbol(url))
    # 5 double_slash_redirecting
    features.append(double_slash_redirecting(url))
    # 6 Prefix_Suffix
    features.append(prefix_suffix(url))
    # 7 having_Sub_Domain
    features.append(having_sub_domain(url))
    # 8 SSLfinal_State
    features.append(ssl_final_state(url))
    # 9 Domain_registeration_length
    features.append(domain_registration_length(domain))
    # 10 Favicon
    features.append(favicon_check(url, domain))
    # 11 port
    features.append(port_check(url))
    # 12 HTTPS_token
    features.append(https_token(url))
    # 13 Request_URL
    features.append(request_url(url, domain))
    # 14 URL_of_Anchor
    features.append(anchor_url(url, domain))
    # 15 Links_in_tags
    features.append(links_in_tags(url, domain))
    # 16 SFH
    features.append(sfh(url))
    # 17 Submitting_to_email
    features.append(submitting_to_email(url))
    # 18 Abnormal_URL
    features.append(abnormal_url(url, domain))
    # 19 Redirect
    features.append(redirect(url))
    # 20 on_mouseover
    features.append(on_mouseover(url))
    # 21 RightClick
    features.append(right_click(url))
    # 22 popUpWidnow
    features.append(popup_window(url))
    # 23 Iframe
    features.append(iframe(url))
    # 24 age_of_domain
    features.append(age_of_domain(domain))
    # 25 DNSRecord
    features.append(dns_record(domain))
    # 26 web_traffic
    features.append(web_traffic(domain))
    # 27 Page_Rank
    features.append(page_rank(domain))
    # 28 Google_Index
    features.append(google_index(domain))
    # 29 Links_pointing_to_page
    features.append(links_pointing_to_page(domain))
    # 30 Statistical_report
    features.append(statistical_report(domain))

    # Sanity: ensure length equals expected number (31)
    if len(features) != len(required_feature_names):
        # pad with 0 if missing
        while len(features) < len(required_feature_names):
            features.append(0)

    # Convert features to matcher values (-1/0/1) if they weren't already
    # (most functions already return -1/0/1)
    meta['features'] = dict(zip(required_feature_names, features))
    return features, meta
