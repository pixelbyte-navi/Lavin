# app.py - Lavin : Website & Message Safety Checker (Streamlit)
# Copy this entire file into your repo as app.py

import streamlit as st
import requests
import socket
import ssl
import whois
import dns.resolver
import tldextract
import pandas as pd
import re
import time
from datetime import datetime
from io import BytesIO
from PIL import Image
from bs4 import BeautifulSoup

# try to import easyocr (works in Streamlit Cloud when added to requirements)
try:
    import easyocr
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

st.set_page_config(page_title="Lavin — Safety Checker", layout="wide")

# ---------- Helpers ----------
def sanitize_url(u):
    if not u:
        return u
    u = u.strip()
    if not re.match(r'^https?://', u):
        u = 'http://' + u
    return u

def fetch_http(url, timeout=8):
    """Return dict with basic HTTP info (status, headers, final_url)."""
    result = {"ok": False, "status_code": None, "headers": {}, "final_url": None, "title": "", "error": None, "response_time": None}
    try:
        t0 = time.time()
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"Lavin/1.0"})
        result["response_time"] = round((time.time()-t0),3)
        result["status_code"] = r.status_code
        result["headers"] = dict(r.headers)
        result["final_url"] = r.url
        result["ok"] = True
        # try to get title
        try:
            bs = BeautifulSoup(r.text, "html.parser")
            t = bs.title.string if bs.title else ""
            result["title"] = t.strip() if t else ""
        except Exception:
            result["title"] = ""
    except Exception as e:
        result["error"] = str(e)
    return result

def check_ssl(host, port=443, timeout=6):
    """Return ssl info: issuer, notAfter, valid (bool), error"""
    info = {"issuer": None, "notAfter": None, "valid": False, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # parse
                issuer = cert.get('issuer')
                issuer_txt = ""
                if issuer:
                    issuer_txt = ", ".join("=".join(x) for x in issuer[0])
                info["issuer"] = issuer_txt
                not_after = cert.get('notAfter')
                info["notAfter"] = not_after
                # validity
                try:
                    # cert notAfter format example: 'Jun  1 12:00:00 2025 GMT'
                    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    info["valid"] = dt > datetime.utcnow()
                except Exception:
                    info["valid"] = True  # if parse fails, assume true (but still show date)
    except Exception as e:
        info["error"] = str(e)
    return info

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return {"error": str(e)}

def dns_records(domain):
    out = {"A": [], "AAAA": [], "MX": [], "NS": []}
    try:
        resolver = dns.resolver.Resolver()
        for t in ["A","AAAA","MX","NS"]:
            try:
                answers = resolver.resolve(domain, t, lifetime=5)
                for rr in answers:
                    out.setdefault(t, []).append(str(rr).strip())
            except Exception:
                out.setdefault(t, [])
    except Exception:
        pass
    return out

url_regex = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)'
    r'(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+'
    r'(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
)

def extract_urls(text):
    found = re.findall(url_regex, text)
    urls = []
    for match in found:
        u = match[0]
        if u:
            u = u.strip()
            # add scheme if missing
            if not re.match(r'^https?://', u):
                u = 'http://' + u
            urls.append(u)
    return list(dict.fromkeys(urls))  # unique preserve order

def domain_from_url(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.registered_domain
        return domain
    except Exception:
        return None

# Simple rule-based text spam/phish detector
PHISH_KEYWORDS = [
    "verify", "password", "account", "bank", "login", "click", "urgent", "update",
    "verify account", "claim", "prize", "free", "limited time", "payment", "ssn"
]

def text_score_and_reasons(text, urls):
    text_lower = text.lower()
    score = 0
    reasons = []
    # presence of URL
    if urls:
        score += 20
        reasons.append("Contains URL(s)")
    # keywords
    kw_count = sum(1 for k in PHISH_KEYWORDS if k in text_lower)
    score += min(30, kw_count * 8)
    if kw_count:
        reasons.append(f"Contains suspicious keywords ({kw_count})")
    # suspicious formatting: urgent caps, exclamation
    if re.search(r'\b(urgent|immediately|asap)\b', text_lower):
        score += 10
        reasons.append("Urgency wording")
    if text.count("!") >= 2:
        score += 5
        reasons.append("Excessive exclamation marks")
    # phone numbers or currency
    if re.search(r'\d{6,}', text):
        score += 5
        reasons.append("Long numeric sequence (possible code/phone/account)")
    # short message + URL often phishing
    if len(text.split()) < 10 and urls:
        score += 10
        reasons.append("Short message with link")
    return min(100, score), reasons

def ocr_image_to_text(img_bytes):
    if not OCR_AVAILABLE:
        return {"error": "OCR not available. Install easyocr in requirements."}
    try:
        reader = easyocr.Reader(['en'], gpu=False)  # load once per call is heavy but acceptable for MVP
        img = Image.open(BytesIO(img_bytes)).convert('RGB')
        res = reader.readtext(np.array(img), detail=0)
        text = "\n".join(res)
        return {"text": text}
    except Exception as e:
        return {"error": str(e)}

# ---------- Streamlit UI ----------
st.markdown("<h1 style='text-align:left'>🔎 Lavin — Website & Message Safety Checker</h1>", unsafe_allow_html=True)
st.info("Only passive checks (HTTP, DNS, WHOIS, SSL, OCR). Do not scan networks without permission. Lavin shows indicators, not guaranteed verdicts.")

with st.sidebar:
    st.header("Input / Options")
    mode = st.selectbox("Mode", ["URL check", "Text / Message", "Image (contains message)"])
    enable_whois = st.checkbox("Run WHOIS (domain age)", value=True)
    enable_dns = st.checkbox("Resolve DNS (A, MX, NS)", value=True)
    enable_ssl = st.checkbox("Check SSL certificate", value=True)
    ocr_opt = st.checkbox("Use OCR on images (easyocr)", value=True)
    st.markdown("---")
    st.write("⚠️ Consent")
    consent = st.checkbox("I have permission to analyze the provided content (or it is public). I accept responsibility.", value=False)
    st.write("Lavin does passive checks only. Use responsibly.")

col1, col2 = st.columns([1,2])

with col1:
    if mode == "URL check":
        input_url = st.text_input("Enter website URL (example: example.com or https://example.com)", "")
        action = st.button("Analyze URL")
    elif mode == "Text / Message":
        input_text = st.text_area("Paste the message / SMS / chat text here", height=180)
        action = st.button("Analyze Text")
    else:
        uploaded_file = st.file_uploader("Upload image (photo of message or screenshot)", type=["png","jpg","jpeg"])
        action = st.button("Analyze Image")

with col2:
    results_placeholder = st.empty()
    evidence_placeholder = st.empty()
    csv_placeholder = st.empty()

if not consent:
    st.warning("Please check the consent box in the sidebar to proceed.")
    st.stop()

# ---------- Main actions ----------
records = []

def analyze_url_flow(url):
    u = sanitize_url(url)
    fetch = fetch_http(u)
    domain = domain_from_url(u)
    who = None
    dnsr = None
    ssl_info = None
    if enable_whois and domain:
        who = get_whois(domain)
    if enable_dns and domain:
        dnsr = dns_records(domain)
    if enable_ssl and domain:
        ssl_info = check_ssl(domain)
    # local heuristics
    score = 0
    evidences = []
    if fetch.get("ok"):
        status = fetch.get("status_code")
        if status and status >= 400:
            score += 20
            evidences.append(f"HTTP status {status}")
        headers = fetch.get("headers") or {}
        server = headers.get("Server") or headers.get("server")
        if server:
            evidences.append(f"Server header: {server}")
    else:
        evidences.append("HTTP fetch failed: " + (fetch.get("error") or "unknown"))
        score += 20
    # ssl
    if ssl_info:
        if ssl_info.get("error"):
            evidences.append("SSL check error: " + ssl_info.get("error"))
            score += 10
        else:
            if not ssl_info.get("valid"):
                evidences.append("SSL certificate appears expired or invalid")
                score += 20
            else:
                evidences.append("SSL valid; expires: " + str(ssl_info.get("notAfter")))
    # whois
    if who:
        try:
            created = who.get("creation_date") or who.get("created_date") or who.get("creation")
            if isinstance(created, list):
                created = created[0]
            if created:
                if isinstance(created, str):
                    # try parse
                    try:
                        created_dt = datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        created_dt = None
                else:
                    created_dt = created
                if created_dt:
                    age_days = (datetime.utcnow() - created_dt).days
                    evidences.append(f"Domain age: {age_days} days")
                    if age_days < 60:
                        score += 15
            else:
                evidences.append("WHOIS: creation date not found")
        except Exception as e:
            evidences.append("WHOIS parse error")
    if dnsr:
        # if no A records, suspicious
        if not dnsr.get("A"):
            evidences.append("No A records found")
            score += 10
    # simple heuristics
    if fetch.get("final_url") and domain and domain not in fetch.get("final_url"):
        evidences.append("Redirects to different domain")
        score += 10
    # final normalization
    verdict = "Likely Legit"
    if score >= 60:
        verdict = "UNSAFE"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    # build record
    record = {
        "input": url,
        "final_url": fetch.get("final_url"),
        "http_status": fetch.get("status_code"),
        "title": fetch.get("title"),
        "score": score,
        "verdict": verdict,
        "evidence": "; ".join(evidences)
    }
    return record, fetch, who, dnsr, ssl_info

def analyze_text_flow(text):
    urls = extract_urls(text)
    score, reasons = text_score_and_reasons(text, urls)
    url_records = []
    for u in urls:
        rec, *_ = analyze_url_flow(u)
        url_records.append(rec)
    verdict = "Likely Legit"
    if score >= 60:
        verdict = "UNSAFE"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    record = {
        "input": text[:200].replace("\n"," "),
        "urls_found": ";".join(urls),
        "text_score": score,
        "verdict": verdict,
        "reasons": "; ".join(reasons)
    }
    return record, url_records

def analyze_image_flow(file_bytes):
    if not OCR_AVAILABLE:
        return {"error":"OCR not available. Add easyocr to requirements."}, []
    try:
        reader = easyocr.Reader(['en'], gpu=False)
        img = Image.open(BytesIO(file_bytes)).convert('RGB')
        import numpy as np
        results = reader.readtext(np.array(img), detail=0)
        text = "\n".join(results)
        rec, urlrecs = analyze_text_flow(text)
        return {"ocr_text": text}, urlrecs
    except Exception as e:
        return {"error": str(e)}, []

if action:
    if mode == "URL check":
        if not input_url:
            st.error("Enter a URL first.")
        else:
            with st.spinner("Analyzing URL..."):
                r, fetch, who, dnsr, sslinfo = analyze_url_flow(input_url)
            results_placeholder.markdown(f"## Verdict: **{r['verdict']}**  \nScore: **{r['score']}**")
            evidence_md = ""
            evidence_md += f"- Final URL: `{r.get('final_url')}`  \n"
            evidence_md += f"- HTTP status: `{r.get('http_status')}`  \n"
            evidence_md += f"- Title: `{r.get('title')}`  \n"
            evidence_md += f"- Evidence: {r.get('evidence')}  \n"
            if who and not isinstance(who, dict):
                try:
                    created = who.creation_date
                    evidence_md += f"- WHOIS creation: `{created}`  \n"
                except Exception:
                    pass
            if dnsr:
                evidence_md += f"- DNS: A `{','.join(dnsr.get('A') or [])}`  \n"
            if sslinfo:
                if sslinfo.get("error"):
                    evidence_md += f"- SSL error: `{sslinfo.get('error')}`  \n"
                else:
                    evidence_md += f"- SSL issuer: `{sslinfo.get('issuer')}`  \n- SSL expiry: `{sslinfo.get('notAfter')}`  \n"
            evidence_placeholder.markdown("### Evidence & details\n" + evidence_md)
            df = pd.DataFrame([r])
            csv = df.to_csv(index=False).encode('utf-8')
            csv_placeholder.download_button("Download result CSV", data=csv, file_name="lavin_url_result.csv", mime="text/csv")
    elif mode == "Text / Message":
        if not input_text:
            st.error("Paste a message first.")
        else:
            with st.spinner("Analyzing text..."):
                rec, urlrecs = analyze_text_flow(input_text)
            results_placeholder.markdown(f"## Verdict: **{rec['verdict']}**  \nScore: **{rec['text_score']}**")
            evidence_md = ""
            evidence_md += f"- Reasons: {rec.get('reasons')}  \n"
            evidence_md += f"- URLs found: `{rec.get('urls_found')}`  \n"
            evidence_placeholder.markdown("### Evidence & details\n" + evidence_md)
            if urlrecs:
                st.markdown("### URL analysis found inside message")
                st.dataframe(pd.DataFrame(urlrecs))
            df = pd.DataFrame([rec])
            csv = df.to_csv(index=False).encode('utf-8')
            csv_placeholder.download_button("Download result CSV", data=csv, file_name="lavin_text_result.csv", mime="text/csv")
    else:
        if not uploaded_file:
            st.error("Upload an image first.")
        else:
            file_bytes = uploaded_file.read()
            with st.spinner("Running OCR and analysis..."):
                ocr_res, urlrecs = analyze_image_flow(file_bytes)
            if "error" in ocr_res:
                results_placeholder.error("OCR error: " + ocr_res["error"])
            else:
                ocr_text = ocr_res.get("ocr_text","")
                rec, _ = analyze_text_flow(ocr_text)
                results_placeholder.markdown(f"## Verdict: **{rec['verdict']}**  \nScore: **{rec['text_score']}**")
                evidence_md = ""
                evidence_md += f"- OCR extracted text (first 500 chars):  \n```\n{ocr_text[:500]}\n```  \n"
                evidence_md += f"- URLs found: `{rec.get('urls_found')}`  \n"
                evidence_placeholder.markdown("### Evidence & details\n" + evidence_md)
                if urlrecs:
                    st.markdown("### URL analysis found inside image")
                    st.dataframe(pd.DataFrame(urlrecs))
                df = pd.DataFrame([rec])
                csv = df.to_csv(index=False).encode('utf-8')
                csv_placeholder.download_button("Download result CSV", data=csv, file_name="lavin_image_result.csv", mime="text/csv")

# Footer
st.markdown("---")
st.caption("Lavin — Passive safety signals only. For educational/demonstration use. Not a replacement for professional security tools.")

