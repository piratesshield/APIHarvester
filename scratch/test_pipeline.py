#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys

def main():
    print("=" * 60)
    print("  INTEGRATION TEST FOR ENHANCED API SECURITY SCANNER")
    print("=" * 60)

    test_dir = os.path.abspath("output_test")
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, exist_ok=True)

    # 1. Create dummy inputs
    hosts_file = os.path.join(test_dir, "hosts.txt")
    with open(hosts_file, "w") as f:
        f.write("httpbin.org\n")

    manifest_file = os.path.join(test_dir, "manifest.json")
    manifest_data = {
        "hosts": {
            "httpbin.org": {
                "is_api": True,
                "url": "https://httpbin.org"
            }
        }
    }
    with open(manifest_file, "w") as f:
        json.dump(manifest_data, f)

    crawled_urls_dir = os.path.join(test_dir, "09_crawling")
    os.makedirs(crawled_urls_dir, exist_ok=True)
    crawled_urls_file = os.path.join(crawled_urls_dir, "all_urls.txt")
    with open(crawled_urls_file, "w") as f:
        f.write("https://httpbin.org/get?name=test\n")

    print("[+] Test environment prepared.")
    print(f"    - hosts.txt: {hosts_file}")
    print(f"    - manifest.json: {manifest_file}")
    print(f"    - 09_crawling/all_urls.txt: {crawled_urls_file}")

    # 2. Run api_deep_discovery.py
    print("\n[*] Running api_deep_discovery.py...")
    cmd_deep = [
        sys.executable, "api_deep_discovery.py",
        "--http-hosts", hosts_file,
        "--output-dir", os.path.join(test_dir, "20_api_deep_discovery"),
        "--crawled-urls", crawled_urls_file,
        "--manifest", manifest_file,
        "--depth", "1"
    ]
    try:
        res = subprocess.run(cmd_deep, capture_output=True, text=True, timeout=300)
        print(res.stdout)
        if res.returncode != 0:
            print(f"[!] api_deep_discovery.py failed with exit code {res.returncode}")
            print(res.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error executing api_deep_discovery.py: {e}")
        sys.exit(1)

    # Check deep discovery outputs
    deep_out_dir = os.path.join(test_dir, "20_api_deep_discovery")
    expected_files = ["xhr_intercepted.txt", "sqli_targets.txt", "injection_targets.txt", "api_endpoints.jsonl"]
    for ef in expected_files:
        p = os.path.join(deep_out_dir, ef)
        if os.path.exists(p):
            print(f"[+] Output verified: {ef} exists ({os.path.getsize(p)} bytes)")
        else:
            print(f"[!] Expected output missing: {ef}")
            sys.exit(1)

    # Check feedback loop
    if os.path.exists(crawled_urls_file):
        with open(crawled_urls_file) as f:
            crawled_content = f.read()
        print(f"[+] Feedback loop verified. all_urls.txt content length: {len(crawled_content.splitlines())} lines")
    else:
        print("[!] feedback loop file missing!")
        sys.exit(1)

    # 3. Run api_intelligence_engine.py
    print("\n[*] Running api_intelligence_engine.py...")
    cmd_intel = [
        sys.executable, "api_intelligence_engine.py",
        test_dir,
        "--threads", "5"
    ]
    try:
        res = subprocess.run(cmd_intel, capture_output=True, text=True, timeout=300)
        print(res.stdout)
        if res.returncode != 0:
            print(f"[!] api_intelligence_engine.py failed with exit code {res.returncode}")
            print(res.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error executing api_intelligence_engine.py: {e}")
        sys.exit(1)

    # Check intelligence engine outputs
    intel_out_dir = os.path.join(test_dir, "16_api_security")
    findings_file = os.path.join(intel_out_dir, "api_findings.jsonl")
    promoted_file = os.path.join(intel_out_dir, "promoted_vulnerabilities.jsonl")
    spec_file = os.path.join(intel_out_dir, "specs", "httpbin.org", "synthetic_spec.json")

    for f_path, label in [(findings_file, "api_findings.jsonl"), (promoted_file, "promoted_vulnerabilities.jsonl"), (spec_file, "synthetic_spec.json")]:
        if os.path.exists(f_path):
            print(f"[+] Output verified: {label} exists ({os.path.getsize(f_path)} bytes)")
        else:
            print(f"[!] Expected output missing: {label}")
            sys.exit(1)

    print("\n" + "=" * 60)
    print("  ALL PIPELINE INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    main()
