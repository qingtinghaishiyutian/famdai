#!/usr/bin/env python3
# ip.py - fetch https://zip.cm.edu.kg/all.txt, keep lines with #SG/#HK/#JP/#TW (case-insensitive),
# dedupe preserving order, save to 中转ip.txt

import re
import sys

URL = "https://zip.cm.edu.kg/all.txt"
OUT_FILE = "cm亚太ip.txt"
PAT = re.compile(r'#(?:sg|hk|jp|tw|kr)\b', re.IGNORECASE)

def fetch_text():
    # 优先使用 requests（workflow 会安装），否则退回 urllib
    try:
        import requests
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; GithubAction/1.0)",
            "Accept": "*/*",
            "Connection": "close",
        }
        r = requests.get(URL, headers=headers, timeout=30)
        r.raise_for_status()
        if not r.encoding:
            r.encoding = r.apparent_encoding or "utf-8"
        return r.text
    except Exception as e_requests:
        # 回退到 urllib
        try:
            from urllib import request
            req = request.Request(URL, headers={
                "User-Agent": "Mozilla/5.0 (compatible; GithubAction/1.0)",
                "Accept": "*/*",
                "Connection": "close",
            })
            with request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            # 尝试多种解码
            for enc in (getattr(resp.headers, "get_content_charset", lambda: None)(),
                        "utf-8", "latin1"):
                if not enc:
                    continue
                try:
                    return data.decode(enc)
                except Exception:
                    pass
            return data.decode("utf-8", errors="replace")
        except Exception as e_urllib:
            print("requests and urllib both failed:", e_requests, e_urllib)
            raise

def filter_lines(text):
    seen = set()
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if PAT.search(line):
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out

def main():
    try:
        text = fetch_text()
    except Exception as e:
        print("Fetch failed:", e)
        sys.exit(1)

    lines = filter_lines(text)
    if not lines:
        print("No matching lines found.")
    else:
        with open(OUT_FILE, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(ln + "\n")
        print(f"Saved {len(lines)} lines to {OUT_FILE}")
    # success exit
    sys.exit(0)

if __name__ == "__main__":
    main()

