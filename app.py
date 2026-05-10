import pickle
import os
import re
import math
from urllib.parse import urlparse
from flask import Flask, request, render_template
import warnings
warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load legacy ML model (used as one signal among many)
try:
    with open(os.path.join(BASE_DIR, 'best_model.pkl'), 'rb') as model_file, \
         open(os.path.join(BASE_DIR, 'best_tfidf.pkl'), 'rb') as tfidf_file:
        model = pickle.load(model_file)
        tfidf = pickle.load(tfidf_file)
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

app = Flask(__name__)

# ─────────────────────────────────────────────
# DETECTION RULES DATABASE
# ─────────────────────────────────────────────

PHISHING_KEYWORDS = {
    # Credential theft
    'verify your account': 15, 'confirm your identity': 15, 'update your password': 15,
    'reset your password': 12, 'login credentials': 15, 'enter your otp': 18,
    'otp has been sent': 12, 'one time password': 12, 'your account has been': 14,
    'account suspended': 16, 'account will be closed': 16, 'account locked': 14,
    'verify immediately': 16, 'click to verify': 14, 'confirm your account': 14,
    'validate your account': 14,

    # Urgency / pressure
    'urgent': 8, 'immediate action': 12, 'act now': 10, 'expires today': 12,
    'expires in 24 hours': 14, 'limited time': 8, 'last chance': 10,
    'final warning': 14, 'your account will be': 10, 'respond immediately': 12,
    'failure to': 10, 'legal action': 12, 'within 24 hours': 10,
    'within 48 hours': 10, 'do not ignore': 10,

    # Financial scams
    'you have won': 18, 'you won': 14, 'congratulations you': 12,
    'claim your prize': 16, 'claim reward': 14, 'lottery winner': 20,
    'selected as winner': 18, 'unclaimed funds': 16, 'cash prize': 14,
    'wire transfer': 12, 'western union': 14, 'moneygram': 14,
    'send money': 10, 'bitcoin': 8, 'cryptocurrency': 8, 'crypto wallet': 12,
    'investment opportunity': 10, 'guaranteed profit': 14, 'get rich': 12,
    'make money fast': 14, 'earn money online': 12,

    # Banking scams
    'bank account': 8, 'credit card details': 16, 'debit card': 10,
    'cvv': 12, 'card number': 10, 'net banking': 10, 'online banking': 8,
    'banking details': 14, 'ifsc code': 12,

    # Fake login
    'click here to login': 14, 'login to your account': 12, 'sign in to': 8,
    'verify your email': 12, 'confirm your email': 12,

    # Delivery scams
    'your package': 6, 'delivery failed': 10, 'reschedule delivery': 12,
    'track your package': 8, 'customs fee': 12, 'delivery fee': 10,

    # Social media scams
    'your account has been hacked': 18, 'someone logged into': 16,
    'unusual activity': 12, 'suspicious login': 14,

    # Generic spam
    'free offer': 10, 'special offer': 6, 'exclusive deal': 8,
    'click here': 8, 'click below': 8, 'subscribe now': 6,
    'no credit card': 8, 'risk free': 8, 'money back guarantee': 8,
    '100% free': 10, 'download now': 6, 'apply now': 6, 'buy now': 6,

    # Indian-specific scams
    'aadhaar': 10, 'pan card': 10, 'kyc update': 14, 'kyc verification': 14,
    'e-kyc': 12, 'update kyc': 14,
    'income tax refund': 14, 'it refund': 12, 'tds refund': 14,
    # Marketing / Promotional spam
    'your workflow': 3, 'going live': 4, 'game changer': 6,
    'hang out with us': 5, 'be the first to know': 7,
    'you won\'t want to miss': 8, 'major addition': 4,
    'transform your': 5, 'daily routine': 3,
    'trim your': 4, 'tech stack': 3, 'monthly subscriptions': 5,
    'save on your': 5, 'expensive': 4, 'disconnected tools': 4,
    'finishing touches': 4, 'digital presence': 3,
    'join our community': 6, 'your input': 3,
    'putting the finishing': 5, 'leaner': 3,
    'powerful dashboard': 5, 'manual digging': 4,
    'endless scrolling': 4, 'shape what comes next': 6,
    'we can\'t wait': 5, 'give you back': 5,
    'hours of your week': 6, 'single powerful': 4,

    # Vague hype language
    'big news': 5, 'exciting news': 5, 'stay tuned': 4,
    'coming soon': 4, 'launching soon': 5, 'go live': 4,
    'sneak peek': 5, 'behind the scenes': 3,
    'next level': 5, 'level up': 5, 'game changing': 6,
    'revolutionary': 6, 'groundbreaking': 6,
    'we\'ve been busy': 4, 'we\'ve been quiet': 4,
    'something big': 6, 'something exciting': 5,
    'dont miss out': 7, 'don\'t miss out': 7,
    'limited spots': 7, 'reserve your spot': 7,
    'early access': 6, 'exclusive access': 6,
    'insider access': 6, 'founding member': 6,
    'join the waitlist': 7, 'join now': 5,
    'sign up free': 6, 'try for free': 5,
    'free trial': 6, 'no commitment': 5,
    'cancel anytime': 4, 'no strings attached': 6,

    # Newsletter / unsubscribe signals
    'you are receiving this': 4, 'you received this': 4,
    'unsubscribe': 3, 'manage preferences': 3,
    'email preferences': 3, 'opt out': 4,
    'update your preferences': 4, 'view in browser': 3,
    'view online': 3, 'this email was sent': 4,

    # Soft upsell
    'upgrade your plan': 6, 'upgrade now': 6,
    'premium features': 5, 'unlock features': 6,
    'unlock premium': 6, 'go premium': 6,
    'boost your': 5, 'supercharge your': 6,
    'skyrocket': 7, 'explode your': 7,
    'passive income': 8, 'side hustle': 6,
    'work from home': 6, 'be your own boss': 7,
    'financial freedom': 7,
}

URGENCY_PATTERNS = [
    r'\bURGENT\b', r'\bIMMEDIATE\b', r'\bACTION REQUIRED\b',
    r'\bIMPORTANT NOTICE\b', r'\bFINAL NOTICE\b', r'\bWARNING\b',
    r'!!+', r'\bASAP\b',
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'short.link',
    'shorte.st', 'adf.ly', 'bitly.com', 'tiny.cc', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'rb.gy',
]

SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.club',
    '.online', '.site', '.website', '.info', '.biz', '.cc', '.ws',
]

TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'apple.com',
    'amazon.com', 'paypal.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'github.com', 'wikipedia.org', 'yahoo.com', 'netflix.com', 'adobe.com',
    'dropbox.com', 'zoom.us', 'slack.com', 'sbi.co.in', 'hdfcbank.com',
    'icicibank.com', 'axisbank.com', 'kotak.com',
]

SUSPICIOUS_ATTACHMENT_PATTERNS = [
    r'\.(exe|bat|cmd|com|pif|scr|vbs|js|jar|msi)\b',
    r'\.(docm|xlsm|pptm|dotm|xltm)\b',
    r'attached (file|document|invoice)',
    r'open the attachment',
    r'download (the )?(attached|file|document)',
]

# ─────────────────────────────────────────────
# URL ANALYSER
# ─────────────────────────────────────────────

def extract_urls(text):
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)

def analyze_url(url):
    score = 0
    reasons = []
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        if re.match(r'\d{1,3}(\.\d{1,3}){3}', domain):
            score += 25
            reasons.append('IP-based URL (no domain name)')

        for short in URL_SHORTENERS:
            if short in domain:
                score += 15
                reasons.append(f'URL shortener detected ({short})')
                break

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 12
                reasons.append(f'Suspicious TLD ({tld})')
                break

        typo_targets = ['paypal', 'google', 'microsoft', 'amazon', 'apple',
                        'facebook', 'netflix', 'bank', 'secure', 'login', 'sbi', 'hdfc']
        for target in typo_targets:
            if target in domain and not any(d == domain or domain.endswith('.' + d)
                                             for d in TRUSTED_DOMAINS):
                score += 18
                reasons.append(f'Typo-squatting / brand impersonation in URL')
                break

        parts = domain.split('.')
        if len(parts) > 4:
            score += 10
            reasons.append('Excessive subdomains in URL')

        sus_url_words = ['login', 'signin', 'verify', 'secure', 'update',
                         'account', 'banking', 'confirm', 'password', 'wallet',
                         'free', 'prize', 'winner', 'claim']
        found_url_kws = [w for w in sus_url_words if w in full]
        if len(found_url_kws) >= 2:
            score += 14
            reasons.append(f'Suspicious URL keywords: {", ".join(found_url_kws[:3])}')
        elif found_url_kws:
            score += 7

        special_count = len(re.findall(r'[%@\-_=&?#]', path))
        if special_count > 8:
            score += 8
            reasons.append('Excessive special characters in URL')

        if parsed.scheme == 'http' and any(w in full for w in ['login', 'secure', 'bank', 'verify']):
            score += 10
            reasons.append('Insecure HTTP for sensitive-looking page')

    except Exception:
        pass
    return score, reasons

# ─────────────────────────────────────────────
# MAIN ANALYSIS ENGINE
# ─────────────────────────────────────────────

def analyze_text(text):
    text_lower = text.lower()
    score = 0
    reasons = []
    matched_keywords = []

    # 1. Keyword matching
    for phrase, weight in PHISHING_KEYWORDS.items():
        if phrase in text_lower:
            score += weight
            reasons.append(f'Phishing phrase: "{phrase}"')
            matched_keywords.append(phrase)

    # 2. Urgency patterns
    for pat in URGENCY_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            score += 8
            reasons.append('Urgency/alarm language detected')
            break

    # 3. ALL-CAPS abuse
    words = text.split()
    if len(words) > 5:
        caps_words = [w for w in words if w.isupper() and len(w) > 2]
        caps_ratio = len(caps_words) / len(words)
        if caps_ratio > 0.3:
            score += 12
            reasons.append(f'Excessive ALL-CAPS usage ({int(caps_ratio*100)}%)')
        elif caps_ratio > 0.15:
            score += 5

    # 4. Exclamation marks
    excl_count = text.count('!')
    if excl_count >= 3:
        score += min(excl_count * 2, 12)
        reasons.append(f'Excessive exclamation marks ({excl_count})')

    # 5. URL analysis
    urls = extract_urls(text)
    for url in urls[:5]:
        url_score, url_reasons = analyze_url(url)
        score += url_score
        reasons.extend(url_reasons)

    # 6. Suspicious attachment references
    for pat in SUSPICIOUS_ATTACHMENT_PATTERNS:
        if re.search(pat, text_lower):
            score += 14
            reasons.append('Suspicious attachment reference')
            break

    # 7. Requests for sensitive info
    sensitive_requests = [
        r'enter (your )?(password|otp|pin|cvv|card number)',
        r'provide (your )?(account|bank|credit card)',
        r'share (your )?(otp|password|credentials)',
        r'do not share (this )?(otp|code|password)',
        r'reply with (your )?(details|account|password)',
    ]
    for pat in sensitive_requests:
        if re.search(pat, text_lower):
            score += 16
            reasons.append('Requests sensitive personal/financial info')
            break

    # 8. Brand impersonation
    impersonation_patterns = [
        r'(paypal|google|microsoft|amazon|apple|facebook|netflix|sbi|hdfc|icici|axis) (support|team|security|help)',
        r'(from|by|team at) (paypal|google|microsoft|amazon|apple|facebook|netflix)',
    ]
    for pat in impersonation_patterns:
        if re.search(pat, text_lower):
            score += 10
            reasons.append('Brand/organization impersonation')
            break

    # 9. Suspicious grammar patterns
    suspicious_grammar = [
        r'\bdear (customer|user|member|friend|sir|madam)\b',
        r'\bkindly (do|click|verify|update|send)\b',
        r'\bplease do the needful\b',
    ]
    for pat in suspicious_grammar:
        if re.search(pat, text_lower):
            score += 6
            reasons.append('Suspicious greeting/phrasing pattern')
            break

    # 10. ML model as additional signal
    if ML_AVAILABLE:
        try:
            transformed = tfidf.transform([text])
            ml_result = model.predict(transformed)[0]
            ml_spam = (ml_result == 1 or ml_result == '1' or
                       str(ml_result).lower() == 'spam')
            if ml_spam:
                score += 10
        except Exception:
            pass

    # Deduplicate reasons
    seen = set()
    unique_reasons = []
    for r in reasons:
        key = r[:45]
        if key not in seen:
            seen.add(key)
            unique_reasons.append(r)

    # Convert score → probability (sigmoid)
    spam_prob_raw = 1 / (1 + math.exp(-0.08 * (score - 30)))
    spam_prob = round(min(max(spam_prob_raw * 100, 1.0), 99.0), 1)
    ham_prob = round(100 - spam_prob, 1)

    if spam_prob >= 10:
        verdict = 'SPAM'
        risk_level = 'CRITICAL RISK' if spam_prob >= 80 else 'HIGH RISK'
    elif spam_prob >= 15:
        verdict = 'SUSPICIOUS'
        risk_level = 'MEDIUM RISK'
    else:
        verdict = 'NOT SPAM'
        risk_level = 'SAFE'

    return {
        'verdict': verdict,
        'risk_level': risk_level,
        'spam_prob': spam_prob,
        'ham_prob': ham_prob,
        'score': score,
        'reasons': unique_reasons[:12],
        'matched_keywords': matched_keywords,
        'url_count': len(urls),
    }

def build_highlighted_text(text, matched_keywords, reasons):
    highlight_terms = set(matched_keywords)
    for reason in reasons:
        m = re.search(r'"([^"]+)"', reason)
        if m:
            highlight_terms.add(m.group(1))
    if not highlight_terms:
        return text, []
    sorted_terms = sorted(highlight_terms, key=len, reverse=True)
    result = text
    for term in sorted_terms:
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        result = pattern.sub(
            lambda m: f'<mark class="spam-word">{m.group(0)}</mark>', result
        )
    return result, sorted_terms[:15]

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('template.html')

@app.route('/predict', methods=['POST'])
def predict():
    email_message = request.form.get('message', '').strip()
    if not email_message:
        return render_template('template.html')

    result = analyze_text(email_message)
    highlighted_text, found_keywords = build_highlighted_text(
        email_message, result['matched_keywords'], result['reasons']
    )

    return render_template(
        'template.html',
        prediction=result['verdict'],
        email_message=email_message,
        highlighted_text=highlighted_text,
        found_keywords=found_keywords,
        spam_prob=result['spam_prob'],
        ham_prob=result['ham_prob'],
        risk_level=result['risk_level'],
        detection_reasons=result['reasons'],
    )

if __name__ == '__main__':
    app.run(debug=True)
