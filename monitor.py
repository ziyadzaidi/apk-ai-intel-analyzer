#!/usr/bin/env python3
"""
APK Domain Intelligence Monitor (v3 - Concurrent High-Volume Edition)
----------------------------------------------------------------------
Handles 300+ domains per day within GitHub Actions time limits by running
web research concurrently (asyncio + aiohttp) and batching Gemini calls.

Pipeline:
1. Pull NRD domains from WhoisDS (free daily feed), filter for "apk".
2. Fire off up to SEARCH_CONCURRENCY parallel real web searches at once
   (DuckDuckGo HTML, no API key) to gather genuine context per domain.
3. Group domains into batches of GEMINI_BATCH_SIZE and send each batch as
   ONE Gemini call (several batches run concurrently, capped by
   GEMINI_CONCURRENCY) so 300 domains only need ~30 AI calls, not 300.
4. If a domain has no real search data, fall back to a transparent,
   clearly-labeled "Estimated (low-confidence)" guess built from the
   domain name's own keyword parts -- never silently blank, but never
   dressed up as verified research either.
5. Export everything to CSV and email it via Gmail SMTP with retries.
"""

import os
import sys
import io
import csv
import json
import time
import random
import base64
import zipfile
import asyncio
import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

import requests
import aiohttp
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
# Any domain containing ANY of these high-value keywords gets captured.
# Checked as a list so nothing valuable slips through.
KEYWORDS = [
    "apk", "mod", "modded", "cheat", "hack", "injector", "modmenu",
    "premium", "pro", "unlocked", "cracked", "xapk", "obb", "ipa",
    "forpc", "downloader",
]
DAYS_BACK_TO_TRY = 3
REQUEST_TIMEOUT = 30
SEARCH_TIMEOUT = 10
GEMINI_TIMEOUT = 25
MAX_EMAIL_RETRIES = 3

# Concurrency knobs -- these are what let us handle 300+ domains fast.
SEARCH_CONCURRENCY = 15      # how many domains get researched at the same time
GEMINI_CONCURRENCY = 5       # how many Gemini batch-calls run at the same time
GEMINI_BATCH_SIZE = 10       # how many domains go into ONE Gemini call
HARD_SAFETY_CAP = 500        # absolute ceiling, protects against a freak data spike

FALLBACK_URL = "https://raw.githubusercontent.com/cenk/nrd/main/nrd-last-10-days.txt"
OUTPUT_FILE = f"apk_domains_{datetime.utcnow().strftime('%Y-%m-%d')}.csv"

GEMINI_MODELS_TO_TRY = ["gemini-1.5-flash", "gemini-2.0-flash"]

SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
RECEIVER_EMAIL = os.environ.get("RECEIVER_EMAIL")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

NOISE_WORDS = {
    "apk", "mod", "modded", "download", "downloader", "free", "app", "apps",
    "game", "games", "get", "latest", "new", "official", "hub", "store",
    "pro", "full", "premium", "cracked", "hack", "cheat", "injector",
    "modmenu", "unlocked", "unlimited", "online", "site", "web", "xapk",
    "obb", "ipa", "forpc",
}

# Simple, transparent heuristics used ONLY when real search data is missing.
# These never claim to be verified -- they just avoid a blank cell.
INTENT_HINTS = [
    (["mod", "hack", "cracked", "unlimited"], "Likely a modded/cracked app distribution site (unauthorized modification of an existing app)."),
    (["download", "free", "get"], "Likely a generic APK download/aggregator portal, not an original app."),
    (["update", "new", "latest"], "Likely positioning itself as an update or news source for an existing app."),
    (["casino", "bet", "slot"], "Likely gambling-related app distribution."),
    (["vpn", "proxy"], "Likely a VPN/proxy utility app."),
]


# ---------------------------------------------------------------------------
# STEP 1: FETCH DOMAINS (synchronous -- this part is a single request, no
# need for concurrency here)
# ---------------------------------------------------------------------------
def fetch_whoisds_domains():
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (apk-domain-monitor)"})

    for days_ago in range(1, DAYS_BACK_TO_TRY + 1):
        target_date = (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        encoded_date = base64.b64encode(f"{target_date}.zip".encode()).decode()
        url = f"https://whoisds.com/whois-database/newly-registered-domains/{encoded_date}/nrd"

        print(f"[WhoisDS] Attempting {target_date} -> {url}")
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            if not resp.content or len(resp.content) < 100:
                continue

            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                txt_files = [n for n in zf.namelist() if n.lower().endswith(".txt")]
                if not txt_files:
                    continue
                with zf.open(txt_files[0]) as f:
                    raw_text = f.read().decode("utf-8", errors="ignore")

            domains = [line.strip().lower() for line in raw_text.splitlines() if line.strip()]
            if domains:
                print(f"[WhoisDS] SUCCESS: {len(domains)} domains for {target_date}.")
                return domains
        except (zipfile.BadZipFile, requests.exceptions.RequestException) as e:
            print(f"[WhoisDS] {target_date} failed: {e}")

    print("[WhoisDS] All attempts exhausted.")
    return []


def fetch_fallback_domains():
    print(f"[Fallback] Attempting {FALLBACK_URL}")
    try:
        resp = requests.get(FALLBACK_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        domains = [line.strip().lower() for line in resp.text.splitlines() if line.strip()]
        print(f"[Fallback] SUCCESS: {len(domains)} domains.")
        return domains
    except requests.exceptions.RequestException as e:
        print(f"[Fallback] Failed: {e}")
        return []


def filter_domains(domains, keywords):
    filtered = sorted(set(d for d in domains if any(k in d for k in keywords)))
    print(f"[Filter] {len(filtered)} domains matched any of {keywords}.")
    if len(filtered) > HARD_SAFETY_CAP:
        print(f"[Filter] Capping at {HARD_SAFETY_CAP} (safety ceiling) out of {len(filtered)}.")
        filtered = filtered[:HARD_SAFETY_CAP]
    return filtered


# ---------------------------------------------------------------------------
# STEP 2: KEYWORD EXTRACTION + OFFLINE FALLBACK GUESS
# ---------------------------------------------------------------------------
def extract_search_term(domain):
    stem = domain.split(".")[0]
    cleaned_stem = stem.lower()
    for noise in NOISE_WORDS:
        cleaned_stem = cleaned_stem.replace(noise, " ")
    cleaned_stem = " ".join(cleaned_stem.split()).strip()
    return cleaned_stem if len(cleaned_stem) >= 3 else stem


def offline_fallback_guess(domain):
    """
    Used ONLY when real web search returns nothing. Produces a clearly
    labeled, low-confidence estimate from the domain name's own words --
    never presented as verified fact.
    """
    stem = domain.lower()
    for keywords, hint in INTENT_HINTS:
        if any(k in stem for k in keywords):
            return {
                "real_category": "Estimated (low-confidence): App/Game-adjacent domain",
                "hidden_intent": f"Estimated (low-confidence, name-based only): {hint}",
            }
    return {
        "real_category": "Estimated (low-confidence): Unclassified app-adjacent domain",
        "hidden_intent": "Estimated (low-confidence, name-based only): No strong keyword signal found in the domain name; likely a generic APK mirror or placeholder site.",
    }


# ---------------------------------------------------------------------------
# STEP 3: CONCURRENT REAL WEB SEARCH
# ---------------------------------------------------------------------------
async def real_web_search_async(session, sem, domain, max_snippets=3):
    query = extract_search_term(domain)
    headers = {"User-Agent": "Mozilla/5.0 (research-bot)"}
    data = {"q": f"{query} apk app"}

    async with sem:
        # small random jitter so we don't hammer DuckDuckGo in one exact instant
        await asyncio.sleep(random.uniform(0.05, 0.3))
        try:
            async with session.post(
                "https://html.duckduckgo.com/html/",
                data=data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=SEARCH_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return domain, []
                html = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return domain, []

    soup = BeautifulSoup(html, "html.parser")
    results = []
    for result in soup.select(".result")[:max_snippets]:
        title_tag = result.select_one(".result__title")
        snippet_tag = result.select_one(".result__snippet")
        link_tag = result.select_one(".result__url")
        title = title_tag.get_text(strip=True) if title_tag else ""
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
        link = link_tag.get_text(strip=True) if link_tag else ""
        if title or snippet:
            results.append((title, snippet, link))

    return domain, results


async def research_all_domains(domains):
    """
    Fires off searches for ALL domains at once, but the semaphore inside
    real_web_search_async caps how many are actually in-flight together
    (SEARCH_CONCURRENCY), so we get speed without overwhelming the search
    engine.
    """
    sem = asyncio.Semaphore(SEARCH_CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=SEARCH_CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [real_web_search_async(session, sem, d) for d in domains]
        results = await asyncio.gather(*tasks)
    return dict(results)  # domain -> [(title, snippet, link), ...]


# ---------------------------------------------------------------------------
# STEP 4: BATCHED GEMINI CALLS
# ---------------------------------------------------------------------------
def build_batch_prompt(batch):
    """
    batch: list of (domain, search_results) tuples.
    Builds ONE prompt covering multiple domains, asking Gemini for a JSON
    array so we spend far fewer API calls than one-per-domain.
    """
    blocks = []
    for domain, search_results in batch:
        if search_results:
            snippet_lines = "\n".join(
                f"  - Title: {t} | Snippet: {s} | Source: {l}"
                for t, s, l in search_results
            )
        else:
            snippet_lines = "  (no real search results found for this domain)"
        blocks.append(f'Domain: "{domain}"\n{snippet_lines}')

    joined_blocks = "\n\n".join(blocks)

    prompt = f"""You are a strict research analyst. For EACH domain listed below,
answer using ONLY the real search results shown for that domain. Do not use
outside knowledge and do not invent facts beyond what the snippets say.

If a domain has NO real search results, say so plainly with
"Insufficient data" for both fields for that domain -- do not guess for it,
that domain will be handled separately by another process.

DOMAINS AND THEIR REAL SEARCH RESULTS:

{joined_blocks}

Respond with STRICT JSON only (a JSON array, no markdown, no extra text),
one object per domain, in the SAME ORDER as listed above, in this exact shape:
[
  {{
    "domain": "the domain name exactly as given",
    "real_category": "short category label, or 'Insufficient data'",
    "hidden_intent": "one or two sentence assessment of likely business
      intent based only on the evidence given, or 'Insufficient data'"
  }}
]
"""
    return prompt


async def call_gemini_batch_async(session, sem, batch):
    prompt = build_batch_prompt(batch)
    domains_in_batch = [d for d, _ in batch]

    async with sem:
        for model in GEMINI_MODELS_TO_TRY:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            params = {"key": GEMINI_API_KEY}
            body = {"contents": [{"parts": [{"text": prompt}]}]}

            for attempt in range(2):  # one retry per model on transient errors
                try:
                    async with session.post(
                        url, params=params, json=body,
                        timeout=aiohttp.ClientTimeout(total=GEMINI_TIMEOUT),
                    ) as resp:
                        if resp.status == 429:
                            await asyncio.sleep(2 + attempt * 3)
                            continue
                        if resp.status != 200:
                            print(f"    [Gemini] {model} returned {resp.status}, trying next.")
                            break

                        data = await resp.json()
                        text = data["candidates"][0]["content"]["parts"][0]["text"]
                        cleaned = text.strip()
                        if cleaned.startswith("```"):
                            cleaned = cleaned.strip("`")
                            cleaned = cleaned.replace("json", "", 1).strip()

                        parsed = json.loads(cleaned)
                        result_map = {
                            item.get("domain", ""): {
                                "real_category": item.get("real_category", "Insufficient data"),
                                "hidden_intent": item.get("hidden_intent", "Insufficient data"),
                            }
                            for item in parsed
                        }
                        return result_map
                except (aiohttp.ClientError, asyncio.TimeoutError, KeyError, IndexError, json.JSONDecodeError) as e:
                    print(f"    [Gemini] {model} attempt {attempt+1} failed: {e}")
                    continue

    # Total failure for this whole batch -- mark all as insufficient,
    # the offline fallback step afterwards will still fill something in
    # for domains that also had no search data.
    return {d: {"real_category": "Insufficient data", "hidden_intent": "Insufficient data"} for d in domains_in_batch}


async def analyze_all_domains_async(domain_search_map):
    """
    Splits all domains into batches of GEMINI_BATCH_SIZE, runs up to
    GEMINI_CONCURRENCY batches at the same time.
    """
    domains = list(domain_search_map.keys())
    batches = []
    for i in range(0, len(domains), GEMINI_BATCH_SIZE):
        chunk = domains[i:i + GEMINI_BATCH_SIZE]
        batches.append([(d, domain_search_map[d]) for d in chunk])

    print(f"[Gemini] {len(domains)} domains split into {len(batches)} batches "
          f"of up to {GEMINI_BATCH_SIZE}, running {GEMINI_CONCURRENCY} at a time.")

    sem = asyncio.Semaphore(GEMINI_CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=GEMINI_CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [call_gemini_batch_async(session, sem, batch) for batch in batches]
        batch_results = await asyncio.gather(*tasks)

    merged = {}
    for result_map in batch_results:
        merged.update(result_map)
    return merged


# ---------------------------------------------------------------------------
# STEP 5: PULL IT ALL TOGETHER
# ---------------------------------------------------------------------------
async def process_domains_async(domains):
    print(f"[Research] Starting concurrent search for {len(domains)} domains "
          f"({SEARCH_CONCURRENCY} at a time)...")
    domain_search_map = await research_all_domains(domains)

    if GEMINI_API_KEY:
        gemini_results = await analyze_all_domains_async(domain_search_map)
    else:
        print("[Gemini] No API key set -- skipping AI step entirely.")
        gemini_results = {}

    rows = []
    for domain in domains:
        search_results = domain_search_map.get(domain, [])
        ai_result = gemini_results.get(domain)

        if ai_result and ai_result.get("real_category") != "Insufficient data":
            category = ai_result["real_category"]
            intent = ai_result["hidden_intent"]
        elif search_results:
            # Search data existed but Gemini failed on it -- still don't
            # silently guess; that's specifically what "Insufficient data"
            # from a real-but-unprocessed search means.
            category = "Insufficient data (AI processing failed)"
            intent = "Insufficient data (AI processing failed)"
        else:
            # No real search data at all -- THIS is where we use the
            # transparent, clearly-labeled offline guess so no cell is blank.
            fallback = offline_fallback_guess(domain)
            category = fallback["real_category"]
            intent = fallback["hidden_intent"]

        sources = "; ".join(link for _, _, link in search_results if link)
        rows.append({
            "Domain": domain,
            "Real Category": category,
            "Hidden Intent/Plan": intent,
            "Sources": sources,
        })

    return rows


# ---------------------------------------------------------------------------
# STEP 6: CSV
# ---------------------------------------------------------------------------
def write_csv(rows, path):
    fieldnames = ["Domain", "Real Category", "Hidden Intent/Plan", "Sources"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"[CSV] Written: {path} ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# STEP 7: EMAIL DELIVERY (SMTP-SAFE, WITH RETRIES)
# ---------------------------------------------------------------------------
def build_message(body_text, attachment_path):
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = f"APK Market Intelligence Report - {datetime.utcnow().strftime('%Y-%m-%d')}"
    msg.attach(MIMEText(body_text, "plain"))

    with open(attachment_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename={attachment_path}")
    msg.attach(part)
    return msg


def send_via_ssl_465(msg):
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=REQUEST_TIMEOUT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)


def send_via_starttls_587(msg):
    context = ssl.create_default_context()
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=REQUEST_TIMEOUT) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)


def send_email_with_retries(msg):
    methods = [("SSL:465", send_via_ssl_465), ("STARTTLS:587", send_via_starttls_587)]
    for method_name, method_func in methods:
        for attempt in range(1, MAX_EMAIL_RETRIES + 1):
            try:
                print(f"[Email] Trying {method_name}, attempt {attempt}/{MAX_EMAIL_RETRIES}...")
                method_func(msg)
                print(f"[Email] SUCCESS via {method_name}.")
                return True
            except (smtplib.SMTPException, OSError, TimeoutError) as e:
                print(f"[Email] {method_name} attempt {attempt} failed: {e}")
                time.sleep(2 ** attempt)
    print("[Email] All SMTP methods and retries exhausted.")
    return False


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    if not all([SENDER_EMAIL, RECEIVER_EMAIL, SENDER_PASSWORD]):
        print("FATAL: Missing email environment variables.")
        sys.exit(1)
    if not GEMINI_API_KEY:
        print("WARNING: GEMINI_API_KEY missing -- AI fields will use offline estimates only.")

    start_time = time.time()

    domains = fetch_whoisds_domains()
    source_used = "WhoisDS"
    if not domains:
        domains = fetch_fallback_domains()
        source_used = "Fallback Mirror"

    if not domains:
        print("FATAL: No data from any source today.")
        sys.exit(1)

    apk_domains = filter_domains(domains, KEYWORDS)

    if not apk_domains:
        rows = []
    else:
        rows = asyncio.run(process_domains_async(apk_domains))

    write_csv(rows, OUTPUT_FILE)

    elapsed = round(time.time() - start_time, 1)
    body_text = (
        f"APK Market Intelligence Report\n"
        f"Date (UTC): {datetime.utcnow().strftime('%Y-%m-%d')}\n"
        f"Source used: {source_used}\n"
        f"Total domains scanned: {len(domains)}\n"
        f"Keyword matches found: {len(apk_domains)}\n"
        f"Processing time: {elapsed} seconds\n\n"
        f"Full details in the attached CSV. Rows marked 'Estimated "
        f"(low-confidence)' had no real search data and are name-based "
        f"guesses only -- treat rows with real category/intent text as the "
        f"verified research.\n"
    )

    msg = build_message(body_text, OUTPUT_FILE)
    email_sent = send_email_with_retries(msg)

    if not email_sent:
        print("WARNING: Email failed after retries. CSV still saved locally "
              "and will be uploaded as a GitHub Actions artifact.")
        sys.exit(0)

    print("Run complete. Email delivered successfully.")


if __name__ == "__main__":
    main()
