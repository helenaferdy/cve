# CVE Monitor - Firewall Vulnerability Monitoring

A FastAPI application that crawls, stores (SQLite), and serves CVE data relevant to core firewall vendors: Fortinet, Check Point, Palo Alto, and Cisco. Provides a REST API to search/filter CVEs by vendor, product, or keyword, with semantic version matching against known affected version ranges.

## Features
- CVE crawling and storage in SQLite
- Search/filter by vendor, product, or keyword
- Semantic version matching against affected ranges
- Multi-pass validation audit logs
- Synchronization status tracking

## Setup
```bash
pip install -r requirements.txt
python main.py
```