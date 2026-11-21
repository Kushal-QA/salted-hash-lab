#!/usr/bin/env python3
"""Build report.pdf from report.md.

Needs:  pip install markdown
and a Chromium-based browser (Edge, Chrome or Chromium) for HTML -> PDF.

Usage:  python3 build_pdf.py [browser-path]
Screenshots: save images next to report.md and replace each [SCREENSHOT: ...]
placeholder with  ![caption](image.png)  then re-run this script.
"""

import os
import shutil
import subprocess
import sys

import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'report.md')
HTML = os.path.join(HERE, 'report.html')
PDF = os.path.join(HERE, 'report.pdf')

CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: 'Times New Roman', Times, serif; font-size: 10.5pt; line-height: 1.35; color: #000; }
h1 { font-size: 20pt; text-align: center; font-weight: normal; margin: 0 0 6pt; }
h1 + p { text-align: center; }
h2 { font-size: 11pt; font-variant: small-caps; text-align: center; margin: 14pt 0 6pt; }
h3 { font-size: 10.5pt; font-style: italic; font-weight: normal; margin: 10pt 0 4pt; }
p { text-align: justify; margin: 0 0 6pt; }
table { border-collapse: collapse; margin: 6pt auto; font-size: 9pt; }
th, td { border: 1px solid #444; padding: 2pt 5pt; vertical-align: top; }
th { background: #eee; }
code { font-family: Consolas, 'Courier New', monospace; font-size: 8.5pt; }
pre { background: #f6f6f6; border: 1px solid #ccc; padding: 4pt; white-space: pre; overflow: hidden; font-size: 6.2pt; line-height: 1.25; }
pre code { font-size: inherit; }
img { max-width: 100%; display: block; margin: 6pt auto; }
"""


def find_browser():
    if len(sys.argv) > 1:
        return sys.argv[1]
    candidates = [
        r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
        r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    ]
    for name in ('chromium', 'chromium-browser', 'google-chrome', 'microsoft-edge'):
        p = shutil.which(name)
        if p:
            candidates.insert(0, p)
    for c in candidates:
        if os.path.isfile(c):
            return c
    sys.exit('No Chromium-based browser found; pass its path as an argument.')


def main():
    with open(SRC, encoding='utf-8') as f:
        body = markdown.markdown(f.read(), extensions=['tables', 'fenced_code'])
    html = ('<!doctype html><html><head><meta charset="utf-8"><title>Report</title>'
            '<style>{}</style></head><body>{}</body></html>').format(CSS, body)
    with open(HTML, 'w', encoding='utf-8') as f:
        f.write(html)
    browser = find_browser()
    subprocess.run([browser, '--headless', '--disable-gpu', '--no-pdf-header-footer',
                    '--print-to-pdf=' + PDF, 'file:///' + HTML.replace('\\', '/')],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.remove(HTML)
    print('Wrote', PDF)


if __name__ == '__main__':
    main()
