# Penetration-Testing-and-Log-Analysis-Lab

## Objective
[Brief Objective - Remove this afterwards]

To simulate a real-world cyberattack by conducting a penetration test on a Windows machine within a controlled virtual environment, identifying vulnerabilities (RDP exploitation via Metasploit), and analyzing attack logs using Splunk. The lab also focused on setting up Sysmon for detailed event logging and implementing effective remediation strategies to enhance system security.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Penetration Testing: Scanning and exploiting vulnerabilities using Metasploit
- Vulnerability Assessment: Identifying open ports (RDP - 3389) and assessing security risks
- Log Analysis: Monitoring and analyzing attack traces using Splunk
- Endpoint Security: Configuring Sysmon for advanced event logging
- Exploitation & Post-Exploitation: Gaining access and understanding attacker techniques

### Tools Used
[Bullet Points - Remove this afterwards]

- Security Information and Event Management (SIEM) system for log ingestion and analysis.(Splunk)
- Sysmon – Configured for advanced event logging
- PowerShell – Used for configuring Sysmon and collecting forensic data
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.
- Kali Linux – Used for scanning and exploiting vulnerabilities
- Nmap – Performed network scanning and port enumeration
- Metasploit Framework – Exploited RDP (port 3389) vulnerability
- VMware – Created and managed the virtual lab environment
- Windows 10 VM – Target system for penetration testing


## Steps
1. Setting Up the Lab Environment
- Created a Windows 10 VM as the target machine
- Installed Kali Linux VM as the attack machine
- Configured network settings for communication between VMs

2. Scanning for Open Ports
Used Nmap to scan the Windows machine and discovered port 3389 (RDP) open
<img src="https://github.com/user-attachments/assets/8c04a768-0a72-4465-9a69-3273fcccc987" /> *Ref 1: Nmap scan output*


3. Exploiting RDP Vulnerability
Launched Metasploit, selected an exploit for RDP (port 3389)
Gained unauthorized access to the Windows machine
<img src="https://github.com/user-attachments/assets/d5bd1f62-003c-4fea-9e0b-054cd22ca089" /> *Ref 2: Metasploit session after successful exploitation*

4. Configuring Sysmon for Log Collection
Installed Sysmon on the Windows VM to capture security events
Configured Sysmon to log process creation, network connections, and registry changes
<img src="https://github.com/user-attachments/assets/5aa5230a-584d-4a35-8b09-d7dfc16c1a86" /> *Ref 3: Sysmon running*

5. Analyzing Logs in Splunk
Installed and configured Splunk to collect and visualize logs
Searched for Indicators of Compromise (IoCs) related to RDP exploitation
<img src="https://github.com/user-attachments/assets/a399302b-0463-44b3-96d5-729130e3132e" /> *Ref 4: Splunk showing logs related to the attack*

8. Implementing Remediation Measures
- Enabled Network Level Authentication (NLA) for RDP security
- Implemented firewall rules to restrict RDP access

<img src="https://github.com/user-attachments/assets/2a881dde-de7c-425f-8518-72181dd2c79c" /> *Ref 5: Enabled Network Level Authentication (NLA) for RDP security*

<img src="https://github.com/user-attachments/assets/17b1152b-ba47-4601-b670-f6a8b064505d" /> *Ref 6: Implemented firewall rules to restrict RDP access to specific IP addresses*


