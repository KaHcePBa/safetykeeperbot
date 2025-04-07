# SafetyKeeper [Telegram bot]

SafetyKeeperBot is a Telegram bot that checks URLs for safety using the VirusTotal API. It detects both explicit and hidden links in messages, analyzes them for threats, and provides detailed results. Ideal for ensuring link safety in chats!

## Features

### 🔍 Link Detection
- **Hidden Links**: Extracts links from `message.entities` (type `text_link`) for hyperlinks embedded in text (e.g., `[link](https://example.com)`).
- **Explicit Links**: Finds URLs in message text using the `URL_PATTERN` regex, including domains without a protocol (e.g., `google.com`).

### 🌐 Handling Links Without Protocol
- Automatically adds `https://` to URLs missing a protocol (e.g., `http://` or `https://`) using the `ensure_protocol` function, aligning with Telegram's default behavior.

### 🛡️ VirusTotal Check
- Utilizes the `virustotal-python` library to scan URLs via the VirusTotal API.
- If no prior report exists, submits the URL for scanning (10-second wait).
- Returns detailed results:
  - Threat indicators: `malicious` and `suspicious` counts.
  - Specific antivirus findings (e.g., "Kaspersky: phishing").
  - Analysis date in a human-readable format (e.g., `28.03.2025, 12:34:56`).

### ⚠️ Limitations
- Processes only the first link found in a message.
- Enforces a 15-second delay between requests to comply with VirusTotal API rate limits.

## Example Output
- **Safe Link**:  
The link https://google.com was detected. Checking with VirusTotal....  
_URL:_ https://google.com  
✅ **Does not contain any suspicious items.**  
Date of analysis: 28.03.2025, 12:34:56 pm.
- **Suspicious Link**:  
The link https://testsafebrowsing.appspot.com/s/phishing.html was detected. Checking with VirusTotal....  
_URL:_ https://testsafebrowsing.appspot.com/s/phishing.html  
⚠️ **Suspicious items detected!**  
👾 _Threats detected:_ 2 antiviruses  
🤔 _Suspicious:_ 1 antivirus  
**Details:**  
_Kaspersky: phishing  
DrWeb: suspicious_  
**Date of analysis:** 28.03.2025, 12:35:10 pm
