# --- src/main.py ---
import os
import nmap
import shodan
import dns.resolver
import dns.reversename
import subprocess
import ipaddress
import requests
import socket
import time
import random
import json
import re

# Optional: load .env if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # dotenv not installed — that's fine, environment variables will still work
    pass

# API KEYS (read from environment)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")    # e.g. export SHODAN_API_KEY="abcd..."
GROQ_API_KEY = os.getenv("GROQ_API_KEY")        # e.g. export GROQ_API_KEY="abcd..."
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

scan_log = ""  # To accumulate results for GROQ

# --- Nmap Scan ---
def nmap_scan(target):
    global scan_log
    print(f"\n[+] Starting Nmap scan on {target}...")
    nm = nmap.PortScanner()
    nm.scan(target, '1-65535', '-v -sS')
    result = f"\n[+] Nmap scan results for {target}:\n"
    for host in nm.all_hosts():
        result += f"Host: {host} ({nm[host].hostname()})\n"
        result += f"State: {nm[host].state()}\n"
        for proto in nm[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]['state']
                result += f"Port: {port}, State: {state}\n"
    print(result)
    scan_log += result + "\n[+] Nmap scan completed.\n"

# --- Shodan Scan ---
def _first_line(text: str) -> str:
    if not text:
        return ""
    return text.strip().split("\n", 1)[0].strip()

def _print_host_block(target_label: str, ip_str: str, org: Optional[str], os_name: Optional[str],
                      open_port_banners: Dict[int, str]):
    # If no open ports → skip output
    if not open_port_banners:
        return ""

    lines = [
        f"\n[+] Shodan scan results for {target_label}:",
        f"IP: {ip_str}",
        f"Organization: {org if org else 'None'}",
        f"Operating System: {os_name if os_name else 'None'}",
    ]

    for p in sorted(open_port_banners.keys()):
        banner = open_port_banners[p]
        if banner:
            lines.append(f"Port {p}: {banner}")
        else:
            lines.append(f"Port {p}: open")

    block = "\n".join(lines)
    print(block)
    return block + "\n"

def shodan_scan(target):
    global scan_log
    if not SHODAN_API_KEY:
        print("[!] SHODAN_API_KEY is not set. Skipping Shodan scan (set the env var to enable).")
        return

    print(f"\n[+] Starting Shodan scan on {target}...")
    api = shodan.Shodan(SHODAN_API_KEY)

    # Resolve all A/AAAA into a set of IPs
    ips = set()
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            for res in socket.getaddrinfo(target, None, fam, socket.SOCK_STREAM):
                ips.add(res[4][0])
    except Exception:
        ips.add(target)

    for ip in sorted(ips):
        try:
            host = api.host(ip)
            org = host.get("org")
            os_name = host.get("os")
            open_port_banners = {}
            for item in host.get("data", []):
                port = item.get("port")
                if isinstance(port, int):
                    open_port_banners[port] = _first_line(item.get("data") or "")
            out = _print_host_block(target, host.get("ip_str", ip), org, os_name, open_port_banners)
            scan_log += out

        except shodan.APIError as e:
            msg = str(e)
            if any(code in msg for code in ("401", "402", "403")):
                try:
                    if ipaddress.ip_address(ip).version == 6:
                        continue  # skip IPv6 (no InternetDB support)
                except Exception:
                    pass
                open_port_banners = {}
                try:
                    r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
                    if r.status_code == 200:
                        data = r.json()
                        for p in data.get("ports", []):
                            open_port_banners[int(p)] = ""  # open, no banner
                except Exception:
                    pass
                out = _print_host_block(target, ip, None, None, open_port_banners)
                scan_log += out
            else:
                continue  # skip IP completely on other errors

    scan_log += "\n[+] Shodan scan completed.\n"

# --- DNS Enumeration ---
def dns_enumeration(target, add_to_scan_log=True):
    """
    DNS enumeration with reverse->forward flow, AAAA records, sorted output, and de-duplication.
    Prints and returns the formatted result string.
    If add_to_scan_log=True and a global `scan_log` exists, it will be appended.
    """
    def _sorted_unique_lines(lines):
        # keep only non-empty lines, sorted for deterministic output
        return "\n".join(sorted({ln for ln in lines if ln.strip()})) + "\n"

    def _collect_forward(domain):
        lines = [f"\n[+] Running forward DNS enumeration for {domain} (from PTR)..."]
        # A
        try:
            a_lines = [f"A Record: {r.address}" for r in dns.resolver.resolve(domain, "A")]
            lines += (a_lines or ["No A records found."])
        except dns.resolver.NoAnswer:
            lines.append("No A records found.")
        except Exception as e:
            lines.append(f"A lookup error: {e}")

        # AAAA
        try:
            aaaa_lines = [f"AAAA Record: {r.address}" for r in dns.resolver.resolve(domain, "AAAA")]
            lines += (aaaa_lines or ["No AAAA records found."])
        except dns.resolver.NoAnswer:
            lines.append("No AAAA records found.")
        except Exception as e:
            lines.append(f"AAAA lookup error: {e}")

        # MX
        try:
            mx_answers = list(dns.resolver.resolve(domain, "MX"))
            if mx_answers:
                for r in mx_answers:
                    lines.append(f"MX Record: {r.exchange} (Priority: {r.preference})")
            else:
                lines.append("No MX records found.")
        except dns.resolver.NoAnswer:
            lines.append("No MX records found.")
        except Exception as e:
            lines.append(f"MX lookup error: {e}")

        # NS
        try:
            ns_answers = list(dns.resolver.resolve(domain, "NS"))
            if ns_answers:
                for r in ns_answers:
                    lines.append(f"NS Record: {r.target}")
            else:
                lines.append("No NS records found.")
        except dns.resolver.NoAnswer:
            lines.append("No NS records found.")
        except Exception as e:
            lines.append(f"NS lookup error: {e}")

        # CNAME
        try:
            cname_answers = list(dns.resolver.resolve(domain, "CNAME"))
            if cname_answers:
                for r in cname_answers:
                    lines.append(f"CNAME Record: {r.target}")
            else:
                lines.append("No CNAME records found.")
        except dns.resolver.NoAnswer:
            lines.append("No CNAME records found.")
        except Exception as e:
            lines.append(f"CNAME lookup error: {e}")

        # TXT
        try:
            txt_answers = list(dns.resolver.resolve(domain, "TXT"))
            if txt_answers:
                for r in txt_answers:
                    # r.strings is deprecated in newer dnspython; use .to_text() and clean quotes
                    txt_val = r.to_text().strip('"')
                    lines.append(f"TXT Record: {txt_val}")
            else:
                lines.append("No TXT records found.")
        except dns.resolver.NoAnswer:
            lines.append("No TXT records found.")
        except Exception as e:
            lines.append(f"TXT lookup error: {e}")

        return _sorted_unique_lines(lines)

    print(f"\n[+] Starting DNS enumeration on {target}...\n")
    header = [f"\n[+] DNS enumeration results for {target}:"]
    body_lines = []

    try:
        # Is it an IP? If this fails, it's a domain.
        ipaddress.ip_address(target)
        # Reverse (PTR)
        try:
            rev_name = dns.reversename.from_address(target)
            ptr = str(dns.resolver.resolve(rev_name, "PTR")[0]).rstrip(".")
            body_lines.append(f"PTR Record: {ptr}")
            # Forward on the resolved domain
            forward_block = _collect_forward(ptr)
            body_lines.append(forward_block.rstrip())  # avoid double trailing newline
        except Exception as e:
            body_lines.append(f"PTR lookup error: {e}")

    except ValueError:
        # It's a domain → do forward lookups directly
        body_lines.append(_collect_forward(target).rstrip())

    result = "\n".join(header + ["\n".join(body_lines)]) + "\n"
    print(result)

    # Optional: add to global scan_log if present
    if add_to_scan_log:
        try:
            global scan_log  # will succeed only if you've defined it elsewhere
            scan_log += result + "\n[+] DNS enumeration completed.\n"
        except NameError:
            pass

    return result

# --- TheHarvester ---
def theharvester_scan(domain):
    global scan_log
    print(f"\n[+] Starting TheHarvester scan on {domain}...\n")
    try:
        result = subprocess.run(
            ['theHarvester', '-d', domain, '-b', 'bing', '-l', '50'],
            capture_output=True, text=True, check=True
        )
        print(result.stdout)
        scan_log += "\n[+] TheHarvester Results:\n" + result.stdout + "\n"
    except subprocess.CalledProcessError as e:
        print(f"TheHarvester Error:\n{e.stderr}")
        scan_log += f"TheHarvester Error:\n{e.stderr}\n"

# --- Gobuster ---
def gobuster_dir_scan(target_url, domain):
    global scan_log
    print(f"\n[+] Starting Gobuster directory scan on {target_url}...\n")
    cmd = [
        'gobuster', 'dir',
        '-u', target_url,
        '-w', '/usr/share/wordlists/dirb/common.txt',
        '-q',
        '--exclude-length', '0'
    ]
    if "mdx.ac.uk" in domain:
        cmd += ['--exclude-length', '266']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print(result.stdout)
            scan_log += f"\n[+] Gobuster Results:\n{result.stdout.strip()}\n"
        else:
            print("[-] No directories found.")
            scan_log += "[-] No directories found.\n"
    except subprocess.CalledProcessError as e:
        print(f"Gobuster Error:\n{e.stderr}")
        scan_log += f"Gobuster Error:\n{e.stderr}\n"

# --- GROQ Summary ---
def _local_summary(scan_results: str) -> str:
    """
    Offline fallback summary with exploitation guidance.
    """
    lines = scan_results.splitlines()

    # Collect open ports
    open_ports = []
    for ln in lines:
        m = re.search(r"\bPort[: ]\s*(\d{1,5})\b.*\bopen\b", ln, re.IGNORECASE)
        if m:
            open_ports.append(int(m.group(1)))

    # DNS highlights
    a_records   = re.findall(r"\bA Record:\s*([0-9.]+)", scan_results)
    mx_records  = re.findall(r"\bMX Record:\s*([^\s]+)", scan_results)
    ns_records  = re.findall(r"\bNS Record:\s*([^\s]+)", scan_results)
    txt_records = re.findall(r"\bTXT Record:\s*(.+)", scan_results)

    # Gobuster
    gobuster_hits = []
    in_gb = False
    for ln in lines:
        if ln.strip().startswith("[+] Gobuster Results"):
            in_gb = True
            continue
        if in_gb and ln.strip():
            gobuster_hits.append(ln.strip())

    # Exploitation suggestions per port
    exploit_notes = []
    for p in sorted(set(open_ports)):
        if p == 21:
            exploit_notes.append("Port 21 (FTP): Try anonymous login or brute-force; check for cleartext creds.")
        elif p == 22:
            exploit_notes.append("Port 22 (SSH): Test weak/default credentials; check for outdated SSH versions.")
        elif p == 23:
            exploit_notes.append("Port 23 (Telnet): Often unencrypted, sniff traffic or brute-force creds.")
        elif p == 25:
            exploit_notes.append("Port 25 (SMTP): Check open relay, enum users with VRFY/EXPN, phishing vectors.")
        elif p in (80, 8080, 443):
            exploit_notes.append(f"Port {p} (HTTP/HTTPS): Run dirbuster/SQLi/XSS checks; try default web creds.")
        elif p == 3306:
            exploit_notes.append("Port 3306 (MySQL): Test weak DB creds, privilege escalation, version exploits.")
        elif p == 3389:
            exploit_notes.append("Port 3389 (RDP): Attempt weak password brute-force; BlueKeep vuln on old Windows.")
        elif p == 445:
            exploit_notes.append("Port 445 (SMB): Check for EternalBlue/MS17-010; try smbclient null sessions.")
        else:
            exploit_notes.append(f"Port {p}: Research default service exploits for this port/service.")

    # Compose report
    parts = []
    parts.append("=== Summary (local fallback with exploitation guidance) ===")
    if open_ports:
        parts.append(f"Open ports: {', '.join(map(str, sorted(set(open_ports))))}")
    else:
        parts.append("No open ports detected.")

    if a_records:
        parts.append(f"A records: {', '.join(a_records)}")
    if mx_records:
        parts.append(f"MX: {', '.join(mx_records)}")
    if ns_records:
        parts.append(f"NS: {', '.join(ns_records)}")
    if txt_records:
        parts.append(f"TXT (sample): {', '.join(txt_records[:3])}")

    if gobuster_hits:
        parts.append("Gobuster found directories (sample):")
        parts.extend(gobuster_hits[:10])

    if exploit_notes:
        parts.append("\n--- Exploitation Techniques ---")
        parts.extend(exploit_notes)

    parts.append("\nNote: This fallback summary is generated offline due to rate limiting. "
                 "For deeper exploit chains, rerun when Groq quota is available.")
    return "\n".join(parts)


def summarize_with_groq(scan_results):
    print("\n Summarizing scan results using GROQ...\n")

    if not GROQ_API_KEY:
        print("[!] GROQ_API_KEY is not set. Using local fallback summary.")
        print("\n GROQ Summary (fallback):\n")
        print(_local_summary(scan_results))
        return

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    # ⚠️ Do not change this prompt text
    prompt = (
        "Summarize and highlight the key findings from this security scan. "
        "Include any critical vulnerabilities, open ports, services, DNS or Shodan findings, "
        "and suggest ways to exploit the target if possible.\n\n"
        f"{scan_results}"
    )

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity assistant who summarizes scan outputs and suggests exploitation paths."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 800
    }

    max_attempts = 2
    MAX_WAIT_CAP = 20

    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)

            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After", "unknown")
                print(f"[!] Rate limited with Retry-After={retry_after}. Falling back to local summary now.")
                print("\n GROQ Summary (fallback):\n")
                print(_local_summary(scan_results))
                return

            resp.raise_for_status()
            reply = resp.json()["choices"][0]["message"]["content"]
            print("\n GROQ Summary:\n")
            print(reply)
            return

        except Exception as e:
            print(f"[!] Error: {e}. Falling back to local summary.")
            print("\n GROQ Summary (fallback):\n")
            print(_local_summary(scan_results))
            return

# --- MAIN ---
if __name__ == "__main__":
    target = input("Enter the target IP or domain: ").strip()

    shodan_scan(target)
    dns_enumeration(target)

    try:
        ipaddress.ip_address(target)
        is_domain = False
    except ValueError:
        is_domain = True

    if is_domain:
        theharvester_scan(target)
        gobuster_dir_scan("https://" + target, target)
    else:
        print("\nSkipping TheHarvester and Gobuster scans (target is an IP address).")

    nmap_scan(target)

    # Final AI Summary
    summarize_with_groq(scan_log)
