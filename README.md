# 🕵️ Automated Reconnaissance Tool

An advanced **cybersecurity reconnaissance tool** that automates the information-gathering phase of penetration testing.  
It integrates multiple open-source tools and APIs to perform domain enumeration, port scanning, subdomain discovery, and vulnerability summarization using **GROQ-powered AI analysis**.

---

## 🧩 Features

- 🔍 **Shodan Scan:** Retrieves public information about the target’s exposed IPs and ports.  
- 🌐 **DNS Enumeration:** Extracts A, AAAA, MX, NS, and TXT records to identify potential infrastructure details.  
- 📧 **Email Harvesting:** Uses *theHarvester* to find associated email addresses for social engineering assessments.  
- 📁 **Directory Bruteforce:** Employs *Gobuster* to discover hidden directories or files.  
- ⚡ **Port Scanning:** Integrates *Nmap* to detect open, closed, or filtered ports and running services.  
- 🤖 **AI Summary (GROQ):** Generates an intelligent report summarizing key findings, vulnerabilities, and exploitation paths.

---

## ⚙️ Installation

```bash
# Clone the repository
git clone git@github.com:madzk33/automated-recon-tool.git
cd automated-recon-tool

python3 -m venv myvenv
source myvenv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Usage
python main.py
Enter SHODAN_API_KEY (leave blank to skip): 
Enter GROQ_API_KEY (leave blank to skip): 
Enter the target IP or domain:
