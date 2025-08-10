import re
import os
import webbrowser
from email import message_from_string
from datetime import datetime

# ------------------------------
# CONFIG
# ------------------------------
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "password", "bank", "account", "click here", "login", "confirm"
]
SUSPICIOUS_EXTENSIONS = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd"]

# ------------------------------
# ANALYSIS FUNCTIONS
# ------------------------------
def analyze_content(email_content):
    findings = []

    # Check keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(rf"\b{keyword}\b", email_content, re.IGNORECASE):
            findings.append(f"Suspicious keyword found: '{keyword}'")

    # Link mismatch detection
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
    for url in urls:
        if "@" in url or "bit.ly" in url:
            findings.append(f"Suspicious or shortened URL: {url}")

    return findings


def analyze_headers(raw_email):
    msg = message_from_string(raw_email)
    findings = []

    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    received = msg.get_all("Received", [])

    if reply_to and reply_to != from_addr:
        findings.append(f"Reply-To address ({reply_to}) differs from From address ({from_addr})")

    if not received:
        findings.append("No Received headers found (could be spoofed)")

    return findings


def scan_attachments(email_content):
    findings = []
    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in email_content.lower():
            findings.append(f"Suspicious attachment type detected: {ext}")
    return findings


# ------------------------------
# HTML REPORT GENERATOR
# ------------------------------
def generate_html_report(content_findings, header_findings, attachment_findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_html = f"""
    <html>
    <head>
        <title>MailSentinel Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #2E86C1; }}
            .safe {{ color: green; }}
            .warning {{ color: red; font-weight: bold; }}
            .section {{ margin-bottom: 20px; }}
            .timestamp {{ font-size: 0.9em; color: gray; }}
        </style>
    </head>
    <body>
        <h1>MailSentinel Security Report</h1>
        <div class="timestamp">Generated on: {timestamp}</div>
        
        <div class="section">
            <h2>Email Content Analysis</h2>
            {format_findings(content_findings)}
        </div>

        <div class="section">
            <h2>Email Header Analysis</h2>
            {format_findings(header_findings)}
        </div>

        <div class="section">
            <h2>Attachment Scan</h2>
            {format_findings(attachment_findings)}
        </div>
    </body>
    </html>
    """

    # Save report
    with open("mailsentinel_report.html", "w", encoding="utf-8") as f:
        f.write(report_html)

    # Get absolute path
    report_path = os.path.abspath("mailsentinel_report.html")
    print(f"\n✅ Report generated successfully!")
    print(f"📂 Report location: {report_path}")

    # Open in browser
    webbrowser.open(f"file://{report_path}", new=2)


def format_findings(findings):
    if not findings:
        return '<p class="safe">No suspicious elements detected.</p>'
    else:
        return "".join([f'<p class="warning">{finding}</p>' for finding in findings])


# ------------------------------
# MAIN FUNCTION
# ------------------------------
def main():
    # Load email from file
    with open("sample_email.txt", "r", encoding="utf-8") as f:
        raw_email = f.read()

    content_findings = analyze_content(raw_email)
    header_findings = analyze_headers(raw_email)
    attachment_findings = scan_attachments(raw_email)

    generate_html_report(content_findings, header_findings, attachment_findings)


if __name__ == "__main__":
    main()
