#!/usr/bin/env python3
import sys
import threading
import time
import random
import re
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
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
class ScannerUI:
    def __init__(self, master):
        self.master = master
        master.title('Critical Vulnerability Scanner')
        
        # Configure window
        master.geometry("900x700")
        master.configure(bg='#1e1e1e')
        
        # Header
        self.header = tk.Label(master, 
                             text="Critical Vulnerability Scanner",
                             font=("Courier", 18, "bold"),
                             fg="#00ff00",
                             bg="#1e1e1e")
        self.header.pack(pady=10)
        
        # Target input
        self.target_frame = tk.Frame(master, bg="#1e1e1e")
        self.target_frame.pack(pady=5)
        
        self.target_label = tk.Label(self.target_frame, 
                                   text="Target URL:",
                                   font=("Courier", 10),
                                   fg="white",
                                   bg="#1e1e1e")
        self.target_label.pack(side=tk.LEFT)
        
        self.target_entry = tk.Entry(self.target_frame, 
                                  width=50,
                                  font=("Courier", 10),
                                  bg="#333333",
                                  fg="white",
                                  insertbackground="white")
        self.target_entry.pack(side=tk.LEFT, padx=5)
        
        # Options frame
        self.options_frame = tk.Frame(master, bg="#1e1e1e")
        self.options_frame.pack(pady=5)
        
        # Threads
        self.threads_label = tk.Label(self.options_frame,
                                     text="Threads:",
                                     font=("Courier", 10),
                                     fg="white",
                                     bg="#1e1e1e")
        self.threads_label.pack(side=tk.LEFT)
        
        self.threads_spin = tk.Spinbox(self.options_frame,
                                      from_=1, to=50,
                                      width=5,
                                      font=("Courier", 10),
                                      bg="#333333",
                                      fg="white")
        self.threads_spin.pack(side=tk.LEFT, padx=5)
        
        # Depth
        self.depth_label = tk.Label(self.options_frame,
                                   text="Depth:",
                                   font=("Courier", 10),
                                   fg="white",
                                   bg="#1e1e1e")
        self.depth_label.pack(side=tk.LEFT)
        
        self.depth_spin = tk.Spinbox(self.options_frame,
                                    from_=1, to=10,
                                    width=5,
                                    font=("Courier", 10),
                                    bg="#333333",
                                    fg="white")
        self.depth_spin.pack(side=tk.LEFT, padx=5)
        
        # Scan button
        self.scan_button = tk.Button(master,
                                   text="Start Scan",
                                   command=self.start_scan,
                                   font=("Courier", 12, "bold"),
                                   bg="#006600",
                                   fg="white",
                                   activebackground="#009900",
                                   activeforeground="white")
        self.scan_button.pack(pady=10)
        
        # Results area
        self.results_frame = tk.Frame(master, bg="#1e1e1e")
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(self.results_frame,
                                                    wrap=tk.WORD,
                                                    width=100,
                                                    height=25,
                                                    font=("Courier", 10),
                                                    bg="#1e1e1e",
                                                    fg="#00ff00",
                                                    insertbackground="white")
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(master,
                                 textvariable=self.status_var,
                                 bd=1,
                                 relief=tk.SUNKEN,
                                 anchor=tk.W,
                                 font=("Courier", 10),
                                 bg="#1e1e1e",
                                 fg="white")
        self.status_bar.pack(fill=tk.X)
        
        # Scanner instance
        self.scanner = CriticalScanner(self.update_status, self.add_result)
    
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            self.update_status("Error: Please enter a target URL", "error")
            return
            
        try:
            threads = int(self.threads_spin.get())
            depth = int(self.depth_spin.get())
        except ValueError:
            self.update_status("Error: Invalid threads or depth value", "error")
            return
            
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Start scan in a new thread to keep UI responsive
        scan_thread = threading.Thread(
            target=self.scanner.scan,
            args=(target, depth, threads),
            daemon=True
        )
        scan_thread.start()
    
    def update_status(self, message, level="info"):
        colors = {
            "info": "white",
            "success": "#00ff00",
            "warning": "#ffff00",
            "error": "#ff0000"
        }
        self.status_var.set(message)
        self.status_bar.config(fg=colors.get(level, "white"))
        self.master.update_idletasks()
    
    def add_result(self, result):
        tag = result.get('type', 'info').lower()
        
        # Configure tags for coloring
        self.results_text.tag_config('critical', foreground='#ff0000', font=('Courier', 10, 'bold'))
        self.results_text.tag_config('high', foreground='#ff6600', font=('Courier', 10, 'bold'))
        self.results_text.tag_config('medium', foreground='#ffff00')
        self.results_text.tag_config('info', foreground='#00ff00')
        
        # Insert the result
        self.results_text.insert(tk.END, f"\n[{time.strftime('%H:%M:%S')}] ", 'info')
        self.results_text.insert(tk.END, f"{result['type']} found at:\n", tag)
        self.results_text.insert(tk.END, f"URL: {result['url']}\n", 'info')
        
        if 'payload' in result:
            self.results_text.insert(tk.END, f"Payload: {result['payload']}\n", 'info')
        if 'parameter' in result:
            self.results_text.insert(tk.END, f"Parameter: {result['parameter']}\n", 'info')
        
        self.results_text.insert(tk.END, f"Confidence: {result['confidence']}\n", 'info')
        self.results_text.insert(tk.END, "-"*80 + "\n", 'info')
        
        self.results_text.see(tk.END)
        self.master.update_idletasks()

# ========== 🛡 SCANNER CORE ==========
class CriticalScanner:
    def __init__(self, status_callback, result_callback):
        self.stop_event = threading.Event()
        self.visited = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.ua = UserAgent()
        self.session.headers.update({'User-Agent': self.ua.random})
        self.status_callback = status_callback
        self.result_callback = result_callback
    
    def scan(self, url, depth=3, threads=10):
        try:
            self.status_callback(f"Starting scan on {url}", "info")
            self.crawl(url, depth, threads)
            
            if not self.stop_event.is_set():
                self.status_callback("Scan completed successfully!", "success")
        except Exception as e:
            self.status_callback(f"Scan failed: {str(e)}", "error")
    
    def crawl(self, url, depth=3, threads=10):
        if depth <= 0 or self.stop_event.is_set():
            return

        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = "http://" + url
            
            with self.lock:
                if url in self.visited:
                    return
                self.visited.add(url)
            
            self.status_callback(f"Scanning: {url}", "info")
            
            # Get page content
            try:
                res = self.session.get(url, timeout=10)
                html = res.text
            except Exception as e:
                self.status_callback(f"Failed to fetch {url}: {str(e)}", "warning")
                return
            
            # Check for critical vulnerabilities
            self.check_sqli(url, html)
            self.check_lfi(url)
            self.check_xss(url, html)
            self.check_rce(url)
            self.check_auth_bypass(url)
            
            # Extract and crawl links
            soup = BeautifulSoup(html, 'html.parser')
            links = {urljoin(url, a['href']) for a in soup.find_all('a', href=True) 
                    if urlparse(urljoin(url, a['href'])).netloc == urlparse(url).netloc}
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for link in links:
                    if link not in self.visited:
                        executor.submit(self.crawl, link, depth-1, threads)
                        
        except Exception as e:
            self.status_callback(f"Error scanning {url}: {str(e)}", "error")
    
    def check_sqli(self, url, html=None):
        """Check for SQL Injection vulnerabilities"""
        sqli_payloads = [
            "'", 
            "\"", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "admin'--"
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            for param in parse_qs(parsed.query):
                for payload in sqli_payloads:
                    test_url = url.replace(f"{param}=", f"{param}={payload}")
                    try:
                        res = self.session.get(test_url, timeout=10)
                        
                        # Common SQL error patterns
                        sql_errors = [
                            "SQL syntax",
                            "MySQL server",
                            "syntax error",
                            "unclosed quotation",
                            "ODBC Driver",
                            "ORA-01756",
                            "quoted string not properly terminated"
                        ]
                        
                        if any(error.lower() in res.text.lower() for error in sql_errors):
                            self.result_callback({
                                "type": "SQL Injection",
                                "url": test_url,
                                "payload": payload,
                                "parameter": param,
                                "confidence": "High"
                            })
                            return True
                    except:
                        continue
        return False
    
    def check_lfi(self, url):
        """Check for Local File Inclusion vulnerabilities"""
        lfi_payloads = [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/hosts",
            "../../../../../../../../windows/win.ini",
            "....//....//....//....//....//....//....//etc/passwd"
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            for param in parse_qs(parsed.query):
                if 'file' in param.lower() or 'page' in param.lower():
                    for payload in lfi_payloads:
                        test_url = url.replace(f"{param}=", f"{param}={payload}")
                        try:
                            res = self.session.get(test_url, timeout=10)
                            
                            # Common LFI indicators
                            if ("root:x:" in res.text or "[extensions]" in res.text or 
                                "[fonts]" in res.text or "[file]" in res.text):
                                self.result_callback({
                                    "type": "Local File Inclusion",
                                    "url": test_url,
                                    "payload": payload,
                                    "parameter": param,
                                    "confidence": "High"
                                })
                                return True
                        except:
                            continue
        return False
    
    def check_xss(self, url, html=None):
        """Check for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><svg/onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            for param in parse_qs(parsed.query):
                for payload in xss_payloads:
                    test_url = url.replace(f"{param}=", f"{param}={payload}")
                    try:
                        res = self.session.get(test_url, timeout=10)
                        if payload in res.text:
                            self.result_callback({
                                "type": "XSS",
                                "url": test_url,
                                "payload": payload,
                                "parameter": param,
                                "confidence": "High"
                            })
                            return True
                    except:
                        continue
        
        # Check forms
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                try:
                    action = form.get('action') or url
                    method = form.get('method', 'get').lower()
                    inputs = {i.get('name'): i.get('value', '') for i in form.find_all(['input', 'textarea'])}
                    
                    for payload in xss_payloads:
                        data = {k: payload for k in inputs}
                        if method == 'post':
                            res = self.session.post(action, data=data, timeout=10)
                        else:
                            res = self.session.get(action, params=data, timeout=10)
                        
                        if payload in res.text:
                            self.result_callback({
                                "type": "XSS",
                                "url": action,
                                "payload": payload,
                                "confidence": "Medium"
                            })
                            return True
                except:
                    continue
        return False
    
    def check_rce(self, url):
        """Check for Remote Code Execution vulnerabilities"""
        rce_payloads = [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "|| id",
            "&& id"
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            for param in parse_qs(parsed.query):
                if 'cmd' in param.lower() or 'command' in param.lower():
                    for payload in rce_payloads:
                        test_url = url.replace(f"{param}=", f"{param}={payload}")
                        try:
                            res = self.session.get(test_url, timeout=10)
                            
                            # Common RCE indicators
                            if ("uid=" in res.text or "gid=" in res.text or 
                                "groups=" in res.text or "Microsoft Windows" in res.text):
                                self.result_callback({
                                    "type": "RCE",
                                    "url": test_url,
                                    "payload": payload,
                                    "parameter": param,
                                    "confidence": "Critical"
                                })
                                return True
                        except:
                            continue
        return False
    
    def check_auth_bypass(self, url):
        """Check for Authentication Bypass vulnerabilities"""
        bypass_payloads = [
            "/.%2e/admin", 
            "/..;/admin", 
            "//admin/", 
            "/admin..%2f",
            "/admin/%0a",
            "/admin/%0d"
        ]
        
        bypass_headers = {
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Forwarded-For": "127.0.0.1"
        }
        
        # Test path bypasses
        for payload in bypass_payloads:
            test_url = urljoin(url, payload)
            try:
                res = self.session.get(test_url, timeout=10)
                if res.status_code == 200:
                    self.result_callback({
                        "type": "Auth Bypass",
                        "url": test_url,
                        "payload": payload,
                        "confidence": "High"
                    })
                    return True
            except:
                continue
        
        # Test header bypasses
        for header, value in bypass_headers.items():
            try:
                headers = {header: value}
                res = self.session.get(url, headers=headers, timeout=10)
                if res.status_code == 200:
                    self.result_callback({
                        "type": "Auth Bypass",
                        "url": url,
                        "payload": f"{header}: {value}",
                        "confidence": "High"
                    })
                    return True
            except:
                continue
        return False

# ========== 🚀 MAIN EXECUTION ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerUI(root)
    root.mainloop()
