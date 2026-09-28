#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("缺少 requests，请先执行：sudo apt install python3-requests -y")
    sys.exit(1)

TIMEOUT = 8
UA = "Mozilla/5.0 (compatible; MyFirstScanner/0.1)"

SECURITY_HEADERS = {
    "X-Content-Type-Options": ("缺少，浏览器可能做 MIME 嗅探，放大 XSS 风险", "低"),
    "X-Frame-Options": ("缺少，可能被点击劫持", "低"),
    "Strict-Transport-Security": ("HTTPS 站点未启用 HSTS，存在被 SSL 降级劫持的可能", "中"),
    "Content-Security-Policy": ("缺少 CSP，XSS 的实际危害会被放大", "低"),
}

DIR_LIST_PATTERNS = ["Index of /", "<title>Directory listing",
                     "Directory Listing For", "<h1>Directory"]

BACKUP_SUFFIX = [".bak", ".old", ".zip", ".rar", ".tar.gz", ".sql",
                 ".swp", ".git", ".svn", ".env"]

ERROR_PATTERNS = [
    ("SQL syntax", "疑似 SQL 报错信息泄露"),
    ("mysql_fetch", "疑似 MySQL 报错信息泄露"),
    ("ORA-", "疑似 Oracle 报错信息泄露"),
    ("Warning:", "疑似 PHP 警告信息泄露"),
    ("Fatal error", "疑似 PHP 致命错误泄露"),
    ("java.lang.", "疑似 Java 异常栈泄露"),
    ("Traceback (most recent call last)", "疑似 Python 异常栈泄露"),
    ("Stack trace:", "疑似异常栈泄露"),
]


def get_title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        return m.group(1).strip()[:80]
    return None


def scan_one(url):
    info = {"url": url, "ok": False, "error": None, "status": None,
            "title": None, "server": None, "findings": []}

    try:
        resp = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT,
                            verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        info["error"] = type(e).__name__
        return info

    info["ok"] = True
    info["status"] = resp.status_code
    info["server"] = resp.headers.get("Server")
    info["title"] = get_title(resp.text)
    findings = info["findings"]

    if resp.status_code == 200:
        for header, (desc, level) in SECURITY_HEADERS.items():
            if header not in resp.headers:
                if header == "Strict-Transport-Security" and not url.startswith("https"):
                    continue
                findings.append({"type": "缺失安全头", "level": level, "detail": desc})

    for h in ("Server", "X-Powered-By"):
        val = resp.headers.get(h)
        if val and re.search(r"\d", val):
            findings.append({"type": "版本信息泄露", "level": "低",
                             "detail": f"{h}: {val}"})

    if resp.status_code == 200:
        for pat in DIR_LIST_PATTERNS:
            if pat.lower() in resp.text.lower():
                findings.append({"type": "目录列出", "level": "中",
                                 "detail": "页面疑似开启了目录浏览"})
                break

    if resp.status_code == 200:
        for suf in BACKUP_SUFFIX:
            if url.lower().endswith(suf):
                findings.append({"type": "疑似备份/源码泄露", "level": "高",
                                 "detail": f"URL 以 {suf} 结尾且返回 200"})
                break

    head_text = resp.text[:20000]
    for pat, desc in ERROR_PATTERNS:
        if pat in head_text:
            findings.append({"type": "报错信息泄露", "level": "中", "detail": desc})
            break

    # 6. 后台地址可访问（我自己加的）
    if resp.status_code == 200:
        for kw in ["admin", "manage", "login", "backend"]:
            if kw in url.lower():
                findings.append({"type": "后台地址可访问", "level": "低",
                                 "detail": f"URL 含关键词 {kw} 且返回 200"})
                break

    return info


def main():
    parser = argparse.ArgumentParser(description="HTTP 响应风险扫描器（雏形）")
    parser.add_argument("file", help="URL 列表文件，每行一个")
    parser.add_argument("-o", "--output", help="结果 JSON 输出路径")
    parser.add_argument("-t", "--threads", type=int, default=10, help="并发数，默认 10")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"找不到文件：{args.file}")
        sys.exit(1)

    fixed = []
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        fixed.append(u)

    if not fixed:
        print("URL 列表是空的。")
        sys.exit(1)

    print("=" * 60)
    print(f"目标数量：{len(fixed)}    并发：{args.threads}")
    print("=" * 60)

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        tasks = {pool.submit(scan_one, u): u for u in fixed}
        for future in as_completed(tasks):
            results.append(future.result())

    results.sort(key=lambda x: x["url"])

    total_findings = 0
    for r in results:
        print(f"\n[URL] {r['url']}")
        if not r["ok"]:
            print(f"  请求失败：{r['error']}")
            continue
        title = r["title"] or "（无标题）"
        print(f"  状态：{r['status']}    标题：{title}")
        if not r["findings"]:
            print("  未发现明显问题")
        for f in r["findings"]:
            total_findings += 1
            print(f"  [{f['level']}] {f['type']} —— {f['detail']}")

    print("\n" + "=" * 60)
    print(f"扫描完成：{len(results)} 个目标，共 {total_findings} 条发现")
    print("=" * 60)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"结果已写入：{args.output}")


if __name__ == "__main__":
    main()
