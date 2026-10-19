#!/usr/bin/env python3
"""Simple explainable URL-warning heuristic; not a reputation service."""
import argparse, ipaddress
from urllib.parse import urlparse
SHORTENERS={"bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","ow.ly"}
WORDS={"login","verify","password","account","secure","update","wallet","urgent","confirm","signin"}
def check_url(raw):
    raw=raw.strip()
    if not raw: return {"url":raw,"risk":"Unknown","score":0,"reasons":["No URL provided"]}
    p=urlparse(raw if "://" in raw else "https://"+raw)
    host=(p.hostname or "").lower().rstrip(".")
    reasons=[]; score=0
    if p.scheme not in ("http","https"): reasons.append("Unexpected URL scheme"); score+=2
    if not host: reasons.append("Could not identify hostname"); score+=3
    if p.username or p.password: reasons.append("User-info appears before hostname"); score+=3
    try:
        ipaddress.ip_address(host); reasons.append("Uses raw IP address instead of domain"); score+=2
    except ValueError: pass
    if host in SHORTENERS: reasons.append("URL shortener hides final destination"); score+=2
    if host.startswith("xn--") or ".xn--" in host: reasons.append("Punycode domain needs careful inspection"); score+=2
    if host.count(".")>=4: reasons.append("Many subdomain levels"); score+=1
    if len(host)>45: reasons.append("Unusually long hostname"); score+=1
    if host.count("-")>=3: reasons.append("Multiple hyphens in hostname"); score+=1
    matched=sorted(w for w in WORDS if w in (host+" "+p.path.lower()))
    if matched: reasons.append("Account/urgency terms: "+", ".join(matched)); score+=1
    if p.scheme=="http": reasons.append("Uses HTTP; this alone does not prove phishing"); score+=1
    risk="High" if score>=5 else "Review" if score>=2 else "Lower signal"
    if not reasons: reasons.append("No configured warning signs found; not proof of safety")
    return {"url":raw,"risk":risk,"score":score,"reasons":reasons}
def main():
    ap=argparse.ArgumentParser(description="Inspect URL warning signs for awareness training.")
    ap.add_argument("url",nargs="?"); a=ap.parse_args()
    result=check_url(a.url if a.url else input("Enter a URL to inspect: "))
    print(f"\nURL: {result['url']}\nHeuristic result: {result['risk']} (score {result['score']})")
    for reason in result["reasons"]: print("- "+reason)
    print("\nThis simple heuristic can produce false positives and false negatives. Do not open suspicious links.")
if __name__=="__main__": main()
