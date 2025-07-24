# 🕵️‍♂️ WHOIS Lookup Tool (Tkinter GUI)

A clean, responsive, and user-friendly WHOIS domain lookup tool built using Python's `tkinter` for GUI and the `python-whois` module for WHOIS queries.

This tool allows users to perform WHOIS lookups on domain names and displays structured results with auto-correction, error handling, and clipboard support.

---

## ✨ Features

- ✅ Real-time WHOIS domain lookup
- ✅ GUI interface (built with `tkinter`)
- ✅ Auto-corrects common user typos (e.g., `example,com` → `example.com`)
- ✅ Detailed WHOIS result formatting
- ✅ Highlights errors in red
- ✅ Threaded background lookup (no UI freezing)
- ✅ Copy results to clipboard with one click
- ✅ Responsive layout with scrollable results
- ✅ Supports Enter key to trigger search

---


## 🔧 Requirements

- Python 3.7+
- Modules:
  - `tkinter` (comes with standard Python)
  - `python-whois`

Install dependencies with:

```bash
pip install python-whois
