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

## 🖼️ Screenshots

| Shodan Results | DNS Enumeration | Email Harvesting | Gobuster & Nmap | AI Summary |
|-----------------|----------------|------------------|-----------------|-------------|
| Shodan Scan |<img width="533" height="645" alt="Screenshot 2025-10-02 211320" src="https://github.com/user-attachments/assets/237ece92-af43-4365-a159-9c556bd8e0b0" />
| DNS Enumeration |<img width="581" height="392" alt="Screenshot 2025-10-02 211338" src="https://github.com/user-attachments/assets/f4d96bc7-3cb0-425d-b62a-e2c09f0803b8" />
| Email Harvesting |<img width="590" height="514" alt="Screenshot 2025-10-02 211353" src="https://github.com/user-attachments/assets/bb58091c-853c-48ff-af6d-8bbe563b1d0c" />
| Gobuster |<img width="555" height="145" alt="Screenshot 2025-10-02 211407" src="https://github.com/user-attachments/assets/41d7644b-b1fb-4905-91e6-b4eec107bf41" />
| Nmap |<img width="454" height="212" alt="Screenshot 2025-10-02 211416" src="https://github.com/user-attachments/assets/01f8f106-c661-44fd-988a-905fa66d32ae" />
| AI Summary & Exploitation Paths |<img width="1886" height="582" alt="Screenshot 2025-10-02 211439" src="https://github.com/user-attachments/assets/22995174-ae02-4e9d-8c86-938652623397" />


*(Screenshots show sample scan results using `example.com`.)*

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
