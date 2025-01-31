# SOC Incident Investigation Report (SIIR) 

# Objective:
I have structured a security incident response framework within a SOC environment using the LetsDefend platform. I analyzed security alerts, investigated potential threats, documented findings, and implemented an effective incident response process to minimize risk and enhance security posture. This project strengthened my expertise in security event analysis, log correlation, threat detection, and incident documentation.

# Skills Learned:
Proficiency in analyzing and responding to SOC alerts using LetsDefend.
Hands-on experience in incident report documentation and threat categorization.
Ability to investigate security incidents using log analysis and correlation techniques.
Application of incident response methodologies for effective containment and mitigation.
Strengthened decision-making skills in identifying false positives versus real threats.

# Tools Used:
LetsDefend: Used for investigating SOC alerts and performing incident analysis.

SIEM (Security Information and Event Management) Tools: For log collection and correlation.

Wireshark: To analyze network traffic related to security incidents.

MITRE ATT&CK Framework: For mapping threats to known TTPs (Tactics, Techniques, and Procedures).

VirusTotal: To check MD5 hash for the file.

AnyRun: Laveraged Sandbox environment to analyze malware in a controlled manner.


# Step-by-Step Breakdown

## Step 1: Alert Generation

Event Trigger: An alert was generated due to the execution of msdt.exe after an Office document was opened on the host jonasPRD (IP: 172.16.17.39).

Vulnerability Identified: The alert was linked to the exploitation of the CVE-2022-30190 vulnerability, known as Follina.

Antivirus Action: The antivirus marked the action as "allowed," indicating no preventive measures were taken.


## Step 2: Detection

File Analysis: The file involved was identified as 05-2022-0438.doc, and its hash was obtained for further investigation.

VirusTotal Check: The file hash was checked on VirusTotal, confirming it exploited the Follina vulnerability.

## Step 3: Initial Access Investigation

Phishing Email Search: The methodology included searching the mailbox for the filename 05-2022-0438.doc to determine if it was received via phishing.

Email Details: An email from adiosputnik[@]ria[.]ru was found, containing the malicious attachment.


## Step 4: Malware Behavior Analysis

Dynamic Analysis: The report emphasized the importance of dynamic analysis to understand the malware's behavior. The file was uploaded to AnyRun for execution.

DNS Request Observation: During execution, a DNS request was made to www.1xml[]formats[.]com, but no meaningful activity was observed.


## Step 5: Historical Analysis

Previous Analysis Check: The report suggested checking past analyses of the file hash to gather more information on its behavior.

Findings from Old Reports: Previous reports indicated that the file had indeed performed malicious activities.


## Step 6: Log Analysis

Network Communication Check: The report instructed searching logs for any device accessing the domain www.1xml[]formats[.]com.

Process History Review: The process history from Endpoint Security was reviewed, confirming that the malware executed successfully and communicated with the command and control (C2) server.


## Step 7: Containment

Device Isolation: After confirming the compromise of the jonasPRD device, immediate action was taken to isolate it from the network to prevent further access by the attacker.


## Step 8: Lessons Learned

Vulnerability Awareness: The report concluded that regular system updates do not guarantee complete protection against attacks, especially with 0-Day vulnerabilities.

Detection Importance: It emphasized the necessity of quick detection and response to minimize damage.


## Step 9: Artifacts Compilation
Documentation of Findings: The report compiled all relevant artifacts, including email addresses, domain names, URLs, and file hashes, to provide a comprehensive overview of the incident.
