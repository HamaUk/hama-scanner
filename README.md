# 🔍 HAMA's Web Vulnerability Scanner v3.1

[![Python](https://img.shields.io/badge/Python-3.6+-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Contributions](https://img.shields.io/badge/Contributions-Welcome-brightgreen)](CONTRIBUTING.md)

Advanced multi-threaded web vulnerability scanner for penetration testers and security researchers.

## ✨ Features

- **XSS Detection**  
  - Tests reflected XSS in parameters/forms  
  - Auto-form detection and manipulation  

- **Bypass Techniques**  
  - Path traversal (`/../admin`)  
  - Header injection (`X-Original-URL`)  

- **Smart Crawling**  
  - Depth-controlled spidering  
  - Multi-threaded scanning  

- **Professional Reporting**  
  - Color-coded terminal output  
  - Detailed vulnerability explanations  

## 🚀 Installation

```bash
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
