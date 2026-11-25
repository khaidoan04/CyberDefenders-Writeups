# CyberDefenders Lab Write-ups (SOC Tier 1 practice)

Write-ups of blue-team labs from [CyberDefenders](https://cyberdefenders.org), done while practising for a SOC Analyst role. Every lab lives in its own folder: a `README.md` with the write-up and an `images/` folder with the screenshots it uses.

Each write-up follows the same structure:

- **Scenario & Objective**: what the lab asks, the category and the tools.
- **Overview**: a short summary of the finding (who, what, when, where, why).
- **Analysis**: how I went through the evidence, step by step, with screenshots.
- **Answer the Questions**: the lab questions with my answers, at the end, so the analysis can be read without spoilers.

Conventions: timestamps are UTC unless stated; external IOCs are defanged (`hxxp[://]`, `203[.]0[.]113[.]5`); internal addresses are left readable; secrets and personal data seen in lab artefacts are redacted. If an analysis has gaps or mistakes, feel free to open an issue.

> **Note:** CyberDefenders asks members not to publish lab answers. Check the platform's current terms before reusing anything from the *Answer the Questions* sections.

## Network forensics

| Lab | Category | Tools |
|---|---|---|
| [DanaBot – Malicious JavaScript Downloader (PCAP)](danabot/README.md) | Network Forensics / Malware Triage | Wireshark, nano (code review), VirusTotal |
| [JetBrains TeamCity – Web Server Compromise](jetbrains/README.md) | Network Forensics | Wireshark, CyberChef, IP geolocation lookup |
| [NerisBot – Suricata and Zeek Log Investigation](nerisbot/README.md) | Network Forensics | Splunk (SPL), Suricata, Zeek, VirusTotal |
| [Poisoned Credentials – LLMNR / NBT-NS / mDNS Poisoning](poisoned-credentials/README.md) | Network Forensics | Wireshark |
| [PsExec Hunt – Lateral Movement over SMB](psexec-hunt/README.md) | Network Forensics | Wireshark |
| [RetailBreach – Stored XSS and Path Traversal](retailbreach/README.md) | Network Forensics | Wireshark, CyberChef, IP geolocation lookup |
| [Tomcat Takeover – Brute Force, WAR Upload and Persistence](tomcat/README.md) | Network Forensics | Wireshark, CyberChef, IP geolocation lookup |
| [WebStrike – Web Shell Upload and Reverse Shell](webstrike/README.md) | Network Forensics | Wireshark, whatismyipaddress.com |
| [XXE Infiltration – Scan, XXE File Read and Database Config Leak](xxe-infiltration/README.md) | Network Forensics | Wireshark, IP geolocation lookup, VirusTotal |

## Memory forensics

| Lab | Category | Tools |
|---|---|---|
| [Amadey – Memory Forensics (Windows 7 x64)](amadey/README.md) | Memory Forensics | Volatility, VirusTotal |
| [RedLine – Memory Forensics (Windows 10 Dump)](redline/README.md) | Memory Forensics | Volatility 3 (`pslist`, `netscan`, `malfind`), `strings`, VirusTotal |
| [Reveal – Memory Forensics (PowerShell and WebDAV Rundll32)](reveal/README.md) | Memory Forensics | Volatility 3 (`windows.info`, `pslist`, `cmdline`, `malfind`, `getsids`), VirusTotal, MITRE ATT&CK |
| [Volatility Traces – Defender Exclusions and RegSvcs Children](volatility-traces/README.md) | Memory Forensics | Volatility 3 (`pslist`, `psscan`, `cmdline`, `getsids`), MITRE ATT&CK |

## SIEM & cloud (Splunk)

| Lab | Category | Tools |
|---|---|---|
| [AWS Raid – CloudTrail Investigation in Splunk](aws-raid/README.md) | Cloud Forensics (Splunk) | Splunk (SPL), AWS CloudTrail |
| [REvil – Ransomware Investigation in Splunk](revil/README.md) | SIEM Investigation (Splunk) | Splunk (SPL), Sysmon, CyberChef, VirusTotal |
| [ShadowRoast – Active Directory Attack Investigation in Splunk](shadowroast/README.md) | SIEM Investigation (Splunk) | Splunk (SPL), Sysmon, Windows Security logs, VirusTotal |

## Endpoint, disk & mobile forensics

| Lab | Category | Tools |
|---|---|---|
| [Andromeda Bot (UNC4210) – USB-Delivered Malware](andromeda-bot/README.md) | Endpoint Forensics | MemProcFS, EvtxECmd, Timeline Explorer, VirusTotal, Google/Mandiant threat-intelligence article |
| [The Crime – Android Forensics with ALEAPP](the-crime/README.md) | Mobile Forensics | ALEAPP (Android Logs, Events And Protobuf Parser) report viewer |
| [XMRig Miner on a Linux Server – Disk Image Forensics](xmrig/README.md) | Disk Forensics (Linux) | `losetup`, `fdisk`, `mount`, `md5sum`, PhotoRec, VirusTotal |

## Malware analysis & threat intelligence

| Lab | Category | Tools |
|---|---|---|
| [3CX Supply Chain Compromise](3cx-supply-chain/README.md) | Malware Analysis / Threat Intelligence | Kali Linux (`msiinfo`, `7z`, `sha256sum`), VirusTotal, MITRE ATT&CK |
| [Oski Stealer – Any.run Triage of a Malicious PowerPoint](oski/README.md) | Malware Analysis / Threat Intelligence | Any.run, VirusTotal, MITRE ATT&CK |
| [Red Stealer – RedLine Sample Triage](red-stealer/README.md) | Malware Analysis / Threat Intelligence | VirusTotal (detection, behaviour, relations), MalwareBazaar, Malpedia |
| [Yellow RAT – Yellow Cockatoo Threat Intelligence](yellow-rat/README.md) | Malware Analysis / Threat Intelligence | VirusTotal, Red Canary threat intelligence report |

## Phishing & OSINT

| Lab | Category | Tools |
|---|---|---|
| [Lespion – OSINT Investigation](lespion/README.md) | OSINT | GitHub, CyberChef, Google Maps, public webcams |
