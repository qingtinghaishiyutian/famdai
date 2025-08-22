#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中转/ip.py
从 https://zip.cm.edu.kg/all.txt 拉取数据，筛选包含 #SG/#HK/#JP/#TW/#KR 的行并去重，
并发检测 IP 可达性（先 ping，ping 失败则尝试 TCP 80/443），按每国上限保存结果。
输出文件：与脚本同目录下的 中转ip.txt（脚本不会自动创建目录）。
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import sys
import subprocess
import platform
import socket
from pathlib import Path
from typing import Optional, Dict, List, Tuple

URL = "https://zip.cm.edu.kg/all.txt"
OUT_FILE = "cm亚太ip.txt"

# 要支持的国家标签（小写）
COUNTRIES = ["sg", "hk", "jp", "tw", "kr"]

# 每个国家最多保存多少条（你指定的）
MAX_PER_COUNTRY: Dict[str, int] = {"sg": 100, "hk": 50, "jp": 50, "tw": 50, "kr": 50}

# 正则匹配标签与 IPv4（支持可选的 /n 后缀）
PAT_TAG = re.compile(r'#(?:sg|hk|jp|tw|kr)\b', re.IGNORECASE)
RE_IPV4 = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?')

# 超时设置（秒）
PING_TIMEOUT = 2.0
TCP_TIMEOUT = 1.0

# 并发线程数（可调）
MAX_WORKERS = 8


def fetch_text() -> str:
    """优先使用 requests，否则使用 urllib 回退。返回文本（str）。"""
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
        try:
            from urllib import request
            req = request.Request(URL, headers={
                "User-Agent": "Mozilla/5.0 (compatible; GithubAction/1.0)",
                "Accept": "*/*",
                "Connection": "close",
            })
            with request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                content_type = None
                try:
                    content_type = resp.headers.get('Content-Type')
                except Exception:
                    pass
        except Exception as e_urllib:
            print("requests and urllib both failed:", e_requests, e_urllib)
            raise

        charset = None
        if content_type:
            m = re.search(r'charset=([^\s;]+)', content_type, flags=re.I)
            if m:
                charset = m.group(1).strip('"\'')

        for enc in (charset, "utf-8", "latin1"):
            if not enc:
                continue
            try:
                return data.decode(enc)
            except Exception:
                pass
        return data.decode("utf-8", errors="replace")


def extract_ipv4(line: str) -> Optional[str]:
    """从行中提取 IPv4（忽略可能的 /n 后缀），并简单校验每段在 0-255。"""
    m = RE_IPV4.search(line)
    if not m:
        return None
    ip = m.group(1)
    parts = ip.split('.')
    for p in parts:
        try:
            if not (0 <= int(p) <= 255):
                return None
        except Exception:
            return None
    return ip


def ping_host(ip: str, timeout: float = PING_TIMEOUT) -> bool:
    """使用系统 ping（-c 1 / -n 1），并用 subprocess.timeout 控制等待时间。"""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout *1000)), ip]
        else:
            cmd = ["ping", "-c", "1", ip]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 0.5)
        return res.returncode == 0
    except Exception:
        return False


def tcp_connect(ip: str, ports=(80, 443), timeout: float = TCP_TIMEOUT) -> bool:
    """尝试连接端口列表，任一成功即认为可达。"""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            continue
    return False


def is_reachable(ip: str) -> bool:
    """先 ping，ping 失败则尝试 TCP 连接 80/443。"""
    if ping_host(ip, timeout=PING_TIMEOUT):
        return True
    return tcp_connect(ip, ports=(80, 443), timeout=TCP_TIMEOUT)


def primary_tag_of_line(line: str) -> Optional[str]:
    """按 COUNTRIES 顺序返回该行的主标签（若包含多个标签，以顺序优先）。"""
    low = line.lower()
    for c in COUNTRIES:
        if f"#{c}" in low:
            return c
    return None


def collect_candidates(text: str) -> List[Tuple[int, str, str, str]]:
    """
    扫描文本并收集候选项（按原始顺序），返回列表 (index, line, tag, ip)。
    去重基于完整行字符串（保留首次出现）。
    """
    seen = set()
    candidates: List[Tuple[int, str, str, str]] = []
    for idx, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line:
            continue
        if not PAT_TAG.search(line):
            continue
        if line in seen:
            continue
        seen.add(line)
        tag = primary_tag_of_line(line)
        if not tag:
            continue
        ip = extract_ipv4(line)
        if not ip:
            continue
        candidates.append((idx, line, tag, ip))
    return candidates


def run_concurrent_tests(candidates: List[Tuple[int, str, str, str]]) -> Tuple[Dict[str, List[Tuple[int, str]]], int]:
    """
    并发检测候选 reachability。
    返回 saved (country -> list[(index,line)]) 与 tested 数量。
    """
    saved: Dict[str, List[Tuple[int, str]]] = {c: [] for c in COUNTRIES}
    tested = 0
    if not candidates:
        return saved, 0

    futures = {}
    workers = min(MAX_WORKERS, max(1, len(candidates)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for cand in candidates:
            idx, line, tag, ip = cand
            fut = ex.submit(is_reachable, ip)
            futures[fut] = cand

        for fut in as_completed(list(futures.keys())):
            cand = futures.get(fut)
            if cand is None:
                continue
            idx, line, tag, ip = cand
            tested += 1
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok and len(saved[tag]) < MAX_PER_COUNTRY.get(tag, 0):
                saved[tag].append((idx, line))
            # 若所有国家都已满额，取消剩余任务并退出
            if all(len(saved[c]) >= MAX_PER_COUNTRY.get(c, 0) for c in COUNTRIES):
                for other_fut in list(futures.keys()):
                    if not other_fut.done():
                        try:
                            other_fut.cancel()
                        except Exception:
                            pass
                break

    # 按原始索引排序每个国家以恢复原始顺序
    for c in COUNTRIES:
        saved[c].sort(key=lambda t: t[0])
    return saved, tested


def write_output(saved: Dict[str, List[Tuple[int, str]]], out_path: Path = OUT_FILE) -> None:
    """
    把保存的行按国家顺序写入文件。
    注意：按你的要求脚本不会自动创建目录；若目录不存在则报错并退出。
    """
    if not out_path.parent.exists():
        print(f"输出目录 {out_path.parent} 不存在。脚本不会自动创建，请先在仓库中创建该目录并提交（或确保 workflow 创建）。")
        sys.exit(2)

    lines: List[str] = []
    for c in COUNTRIES:
        lines.extend([ln for (_, ln) in saved.get(c, [])])

    try:
        with out_path.open("w",encoding="utf-8", newline="\n") as f:
            for ln in lines:
                f.write(ln + "\n")
    except Exception as e:
        print(f"写入文件 {out_path} 失败: {e}")
        raise


def main():
    try:
        text = fetch_text()
    except Exception as e:
        print("Fetch failed:", e)
        sys.exit(1)

    candidates = collect_candidates(text)
    if not candidates:
        print("No candidates found for tags.")
        sys.exit(0)

    saved, tested = run_concurrent_tests(candidates)
    total_saved = sum(len(v) for v in saved.values())

    if total_saved == 0:
        print(f"No reachable lines found (tested {tested} candidates).")
    else:
        write_output(saved, OUT_FILE)
        print(f"Saved {total_saved} lines to {OUT_FILE} (tested {tested} candidates).")
        for c in COUNTRIES:
            print(f"  {c.upper()}: saved {len(saved.get(c, []))}/{MAX_PER_COUNTRY.get(c)}")

    sys.exit(0)


if __name__ == "__main__":
    main()

