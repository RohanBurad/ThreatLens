import re
import socket
import ssl
import urllib.parse
import requests
import whois
from datetime import datetime, timezone
import tldextract

# ─── Suspicious keyword lists ────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'banking',
    'confirm', 'password', 'credential', 'paypal', 'amazon', 'apple',
    'google', 'microsoft', 'netflix', 'ebay', 'wallet', 'suspended',
    'unusual', 'limited', 'access', 'click', 'free', 'prize', 'winner',
    'urgent', 'alert', 'notice', 'suspended', 'blocked', 'locked'
]

TRUSTED_TLDS = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co'}
SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link', '.online'}

# ─── Popular domains for typosquat detection ─────────────────────────────────
POPULAR_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com',
    'linkedin.com', 'github.com', 'reddit.com', 'wikipedia.org', 'yahoo.com',
    'ebay.com', 'dropbox.com', 'spotify.com', 'adobe.com', 'whatsapp.com',
    'tiktok.com', 'pinterest.com', 'snapchat.com', 'tumblr.com', 'twitch.tv',
]


# ─── Typosquat Detection ─────────────────────────────────────────────────────

def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def check_typosquat(url: str) -> dict:
    result = {'is_typosquat': False, 'similar_to': None, 'edit_distance': None}
    try:
        ext = tldextract.extract(url)
        input_full = f"{ext.domain}.{ext.suffix}".lower()

        for popular in POPULAR_DOMAINS:
            if input_full == popular:
                return result

            pop_ext = tldextract.extract(popular)
            pop_domain = pop_ext.domain.lower()
            input_domain = ext.domain.lower()

            dist = levenshtein(input_domain, pop_domain)

            if dist <= 2 and abs(len(input_domain) - len(pop_domain)) <= 2:
                result['is_typosquat'] = True
                result['similar_to'] = popular
                result['edit_distance'] = dist
                return result

    except Exception:
        pass
    return result


# ─── DNS Resolution Check ─────────────────────────────────────────────────────

def check_dns(hostname: str) -> dict:
    result = {'resolves': False, 'ip_address': None}
    try:
        ip = socket.gethostbyname(hostname)
        result['resolves'] = True
        result['ip_address'] = ip
    except socket.gaierror:
        pass
    return result


# ─── Feature extraction ───────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    features = {}
    parsed = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    full_url = url.lower()
    ext = tldextract.extract(url)

    features['url_length'] = len(url)
    features['uses_https'] = parsed.scheme == 'https'
    features['ip_in_url'] = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))
    features['dot_count'] = url.count('.')
    features['special_char_count'] = sum(url.count(c) for c in ['@', '!', '#', '%', '=', '?', '&', '-', '_'])

    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    features['subdomain_depth'] = len([s for s in subdomains if s])

    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    features['phishing_keywords'] = found_keywords
    features['keyword_count'] = len(found_keywords)

    tld = '.' + ext.suffix if ext.suffix else ''
    features['tld'] = tld
    features['suspicious_tld'] = tld.lower() in SUSPICIOUS_TLDS
    features['domain_length'] = len(ext.domain)
    features['hyphen_in_domain'] = '-' in ext.domain
    features['digit_in_domain'] = bool(re.search(r'\d', ext.domain))

    path_parts = [p for p in path.split('/') if p]
    features['path_depth'] = len(path_parts)

    features['has_at_symbol'] = '@' in url
    features['has_double_slash'] = '//' in path
    features['has_hex_encoding'] = '%' in url

    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']
    features['is_shortened'] = any(s in full_url for s in shorteners)

    brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'instagram']
    features['brand_impersonation'] = any(
        brand in ext.domain.lower() and ext.domain.lower() != brand
        for brand in brands
    ) or any(
        brand in ext.subdomain.lower()
        for brand in brands
    )

    return features


def check_ssl(hostname: str) -> dict:
    ssl_info = {'valid': False, 'issuer': None, 'expiry': None, 'days_remaining': None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            ssl_info['valid'] = True
            ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
            expiry_str = cert.get('notAfter', '')
            if expiry_str:
                expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                ssl_info['expiry'] = expiry.strftime('%Y-%m-%d')
                ssl_info['days_remaining'] = (expiry - datetime.now(timezone.utc)).days
    except Exception:
        pass
    return ssl_info


def check_domain_age(url: str) -> dict:
    age_info = {'creation_date': None, 'age_days': None, 'registrar': None}
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_info['creation_date'] = creation.strftime('%Y-%m-%d')
            age_info['age_days'] = (datetime.now(timezone.utc) - creation).days
        age_info['registrar'] = w.registrar
    except Exception:
        pass
    return age_info


def check_virustotal(url: str, api_key: str = None) -> dict:
    if not api_key:
        return None
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        headers = {'x-apikey': api_key}
        r = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=8)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'clean': stats.get('harmless', 0),
                'total': sum(stats.values())
            }
    except Exception:
        pass
    return None


# ─── Scoring Engine ───────────────────────────────────────────────────────────

def compute_risk_score(features: dict, ssl_info: dict, domain_age: dict,
                       typosquat: dict, dns: dict) -> tuple:
    score = 0
    reasons = []
    positive_signals = []

    # --- DNS Check ---
    if not dns['resolves']:
        score += 30
        reasons.append(('Domain does not resolve — site does not exist or is inactive', 'critical'))
    else:
        positive_signals.append(f"Domain resolves to {dns['ip_address']}")

    # --- Typosquat Check ---
    if typosquat['is_typosquat']:
        score += 35
        reasons.append((
            f"Typosquat detected — very similar to '{typosquat['similar_to']}' "
            f"(only {typosquat['edit_distance']} character(s) different)",
            'critical'
        ))

    # --- Existing signals ---
    if features['ip_in_url']:
        score += 25
        reasons.append(('IP address used instead of domain name', 'critical'))

    if not features['uses_https']:
        score += 20
        reasons.append(('No HTTPS — connection is not encrypted', 'high'))

    if features['has_at_symbol']:
        score += 15
        reasons.append(('@ symbol in URL — often used to disguise the real destination', 'high'))

    if features['brand_impersonation']:
        score += 30
        reasons.append(('Known brand name found in suspicious position in domain', 'critical'))

    if features['is_shortened']:
        score += 15
        reasons.append(('URL shortener detected — hides real destination', 'medium'))

    if features['suspicious_tld']:
        score += 20
        reasons.append((f"Suspicious top-level domain: {features['tld']}", 'high'))

    if features['keyword_count'] >= 3:
        score += 20
        reasons.append((f"Multiple phishing keywords: {', '.join(features['phishing_keywords'][:5])}", 'high'))
    elif features['keyword_count'] >= 1:
        score += 8
        reasons.append((f"Phishing keyword(s) detected: {', '.join(features['phishing_keywords'])}", 'medium'))

    if features['subdomain_depth'] >= 3:
        score += 15
        reasons.append((f"Excessive subdomain depth ({features['subdomain_depth']} levels)", 'high'))
    elif features['subdomain_depth'] == 2:
        score += 5
        reasons.append(('Multiple subdomain levels — worth checking', 'low'))

    if features['url_length'] > 100:
        score += 10
        reasons.append((f"Very long URL ({features['url_length']} chars)", 'medium'))
    elif features['url_length'] > 75:
        score += 5
        reasons.append((f"Long URL ({features['url_length']} chars)", 'low'))

    if features['has_hex_encoding']:
        score += 10
        reasons.append(('URL contains hex encoding', 'medium'))

    if features['hyphen_in_domain']:
        score += 5
        reasons.append(('Hyphen in domain — common in phishing imitation domains', 'low'))

    if features['digit_in_domain']:
        score += 5
        reasons.append(('Digits in domain name — unusual for legitimate sites', 'low'))

    if features['has_double_slash']:
        score += 8
        reasons.append(('Double slash in URL path — possible redirect trick', 'medium'))

    if domain_age.get('age_days') is not None:
        if domain_age['age_days'] < 30:
            score += 25
            reasons.append((f"Domain is only {domain_age['age_days']} days old — very new", 'critical'))
        elif domain_age['age_days'] < 180:
            score += 10
            reasons.append((f"Domain is {domain_age['age_days']} days old — relatively new", 'medium'))

    if ssl_info.get('valid'):
        if ssl_info.get('days_remaining', 999) < 10:
            score += 10
            reasons.append(('SSL certificate expires very soon', 'medium'))
        else:
            positive_signals.append('Valid SSL certificate')
    elif features['uses_https']:
        score += 5
        reasons.append(('HTTPS used but SSL could not be verified', 'low'))

    # --- Positive signals (context-aware) ---
    # Only add "established domain" if it's NOT a typosquat
    if domain_age.get('age_days') and domain_age['age_days'] > 365 and not typosquat['is_typosquat']:
        positive_signals.append(f"Established domain ({domain_age['age_days']} days old)")

    if features['uses_https'] and ssl_info.get('valid'):
        positive_signals.append('Secure HTTPS connection with valid certificate')

    if not features['suspicious_tld'] and features['tld'] in TRUSTED_TLDS:
        positive_signals.append(f"Trusted TLD: {features['tld']}")

    if features['keyword_count'] == 0:
        positive_signals.append('No phishing keywords detected')

    score = min(score, 100)

    # --- Suppress misleading positives when critical threats exist ---
    critical_flags = [r for r in reasons if r[1] == 'critical']
    if len(critical_flags) >= 2:
        # Multiple critical issues — clear all positive signals
        positive_signals = []
    elif len(critical_flags) == 1:
        # One critical issue — keep only genuinely meaningful positives
        positive_signals = [s for s in positive_signals if 'SSL' in s or 'resolves' in s]

    if score >= 70:
        verdict = 'PHISHING'
        verdict_label = '🚨 Likely Phishing'
        color = 'danger'
    elif score >= 40:
        verdict = 'SUSPICIOUS'
        verdict_label = '⚠️ Suspicious'
        color = 'warning'
    else:
        verdict = 'SAFE'
        verdict_label = '✅ Likely Safe'
        color = 'safe'

    return score, verdict, verdict_label, color, reasons, positive_signals


# ─── Main entry point ─────────────────────────────────────────────────────────

def analyze_url(url: str, vt_api_key: str = None) -> dict:
    if not url.startswith(('http://', 'https://')):
        url_for_check = 'https://' + url
    else:
        url_for_check = url

    parsed = urllib.parse.urlparse(url_for_check)
    hostname = parsed.hostname or ''

    features   = extract_features(url_for_check)
    ssl_info   = check_ssl(hostname)
    domain_age = check_domain_age(url_for_check)
    typosquat  = check_typosquat(url_for_check)
    dns        = check_dns(hostname)
    vt_result  = check_virustotal(url_for_check, vt_api_key)

    score, verdict, verdict_label, color, reasons, positive_signals = compute_risk_score(
        features, ssl_info, domain_age, typosquat, dns
    )

    if vt_result and vt_result['malicious'] > 0:
        score = min(100, score + 30)
        reasons.insert(0, (f"VirusTotal: {vt_result['malicious']} engines flagged this URL as malicious", 'critical'))
        verdict = 'PHISHING'
        verdict_label = '🚨 Likely Phishing'
        color = 'danger'

    return {
        'url': url,
        'score': score,
        'verdict': verdict,
        'verdict_label': verdict_label,
        'color': color,
        'reasons': reasons,
        'positive_signals': positive_signals,
        'features': {
            'url_length': features['url_length'],
            'uses_https': features['uses_https'],
            'subdomain_depth': features['subdomain_depth'],
            'domain_length': features['domain_length'],
            'tld': features['tld'],
            'keyword_count': features['keyword_count'],
            'path_depth': features['path_depth'],
        },
        'ssl': ssl_info,
        'domain_age': domain_age,
        'dns': dns,
        'typosquat': typosquat,
        'virustotal': vt_result,
        'analyzed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }