# 📧 MailSentinel – Phishing Email Detection Tool

MailSentinel is a Python-based **phishing detection and email security tool** designed to scan email **content**, **headers**, and **attachments** for suspicious patterns, phishing links, and malicious file types.  
It provides a **unified security analysis** and generates an **automated HTML report** that opens instantly in your browser.

---

## 🚀 Features
- **Content Analysis** – Detects suspicious keywords, shortened URLs, and link mismatches.
- **Header Analysis** – Identifies spoofing indicators like mismatched `From` and `Reply-To` addresses.
- **Attachment Scanning** – Flags risky file types such as `.exe`, `.bat`, `.vbs`, etc.
- **Automated Reports** – Generates a color-coded HTML report for real-time review.

---

## 🛠️ Tech Stack
- **Language:** Python  
- **Libraries:** `re`, `email`, `datetime`, `webbrowser`  
- **Output:** HTML Report

---


---

## ⚡ How It Works
1. **Input:** Loads raw email data from a `.txt` file.
2. **Analysis:**
   - Scans content for phishing keywords & malicious URLs.
   - Checks email headers for spoofing attempts.
   - Scans attachments for unsafe file types.
3. **Output:**  
   - Generates an HTML security report.
   - Opens the report directly in your default browser.

---

## 📌 Usage
1️⃣ Clone the repository:
```bash
git clone https://github.com/<your-username>/mailsentinel.git
cd mailsentinel

## Sample HTML Report

Below is an example of the MailSentinel security report:

![Sample HTML Report](path/to/your-screenshot.png)


## 📂 Project Structure
