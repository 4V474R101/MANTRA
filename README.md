
A<div align="center">

<img  width="308" height="351" alt="image" src="https://github.com/user-attachments/assets/720705e1-7459-4b25-977a-909ba00c245c" />

# 🧘‍♂️ MANTRA
MANTRA — MCP server bridging AI agents to 100+ security tools. C++ server executes nmap, nuclei, sqlmap, hydra, gobuster, subfinder, metasploit, and more. MCP bridge connects LLM Desktop, Cursor, Windsurf, or any MCP-compatible AI-Desk Application. Agent reasons over tool output, plans next step, chains attacks autonomously. Built for pentesting, red teaming, bug bounty, CTF, and security research.

<div align="center">

## 🔥 **FEATURES**
| Feature | Description |
|---------|-------------|
| MCP Protocol | JSON-RPC bridge connects any MCP-compatible AI agent |
| 100+ Security Tools | Nmap, nuclei, sqlmap, hydra, metasploit, and more |
| AI Agent Loop | Agent plans, executes, analyzes output, decides next step autonomously |
| Dynamic Tool Detection | Auto-scans system for installed tools at startup |
| Multi-Platform | LLM Desktop, Cursor, Windsurf, Copilot, Cline, Aider |
| Smart Scan Engine | AI-driven target analysis, tool selection, parameter optimization |
| Attack Chaining | Auto-chains recon → scan → exploit based on results |
| CVE Intelligence | Live CVE monitoring, exploit generation from advisories |
| Bug Bounty Workflows | Pre-built recon, vuln hunting, auth bypass, file upload flows |
| Payload Generation | Buffer, cyclic, random payloads + AI-generated attack suites |
| Process Management | Launch, pause, resume, terminate long-running tools |
| Result Caching | Cache tool output, skip repeated scans |
| Error Recovery | Auto-retry failed tools, suggest alternatives |
| File Operations | Create, read, modify, delete workspace files |
| Python Integration | Install packages, execute scripts on the fly |
| Visual Dashboards | Vulnerability cards, scan summaries, system metrics |
| API Security Suite | GraphQL, JWT, REST fuzzing, schema analysis |
| Cloud/Container | AWS, GCP, Azure, K8s, Docker security audits |
| Binary/PWN/CTF | GDB, Ghidra, ROP gadgets, symbolic execution |
| Forensics/Stego | Memory analysis, file carving, steganography |

<h2>WORKING</h2>

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/7ea25b1b-82b7-4e75-8603-eb07561e1b18" />
<br><br>

<div align="center">

MANTRA is three layers: brain, translator, executor.

**LLM (Brain)** receives your goal in plain English. It breaks the goal into steps, picks which security tool to run first, and generates the right arguments. After each tool runs, LLM reads the output, reasons over results, and decides the next action. It chains tools together — recon feeds into scanning, scanning feeds into exploitation. All decision-making lives here.

**Bridge (Translator)** sits between LLM and the server. LLM speaks MCP protocol over stdin/stdout. Server speaks HTTP. Bridge converts one to the other. No logic, no decisions — pure format conversion.

**Server (Executor)** receives HTTP requests, builds shell commands, runs tools via `popen()`, captures stdout, and returns JSON. It knows 100+ security tools — nmap, nuclei, sqlmap, hydra, metasploit, gobuster, subfinder, and more. It doesn't think. It executes what it's told and returns raw output.

**The loop:** You give a goal → LLM picks a tool → bridge forwards → server executes → output returns → LLM analyzes → picks next tool → repeats until goal is met or nothing left to try.

Key thing: MANTRA doesn't replace these tools. It wraps them so AI can use them autonomously. The real power is LLM chaining tools intelligently — running subfinder, feeding results to httpx, then scanning live hosts with nuclei, all without you typing a single command.




</div>

<div align="left">

<h2>HOW TO USE</h2>

<hr>

<h3>1. Open Google Cloud Console</h3>

<p>
Go to:<br>
https://console.cloud.google.com/
</p>

<hr>

<h3>2. Create a Project & Service Account</h3>

<ol>
  <li>Click the ☰ (top-left menu)</li>
  <li>Go to <b>IAM & Admin → Service Accounts</b></li>
  <li>Click <b>Create Service Account</b></li>
  <li>Create a new project if prompted</li>
</ol>

<p>Service account email example:</p>

<pre>
testdemo-svc@blahblahblah.iam.gserviceaccount.com
</pre>

<hr>

<h3>3. Generate credentials.json</h3>

<ol>
  <li>Click the service account email</li>
  <li>Go to <b>Keys</b></li>
  <li>Add Key → Create New Key → JSON</li>
  <li>Rename to <code>credentials.json</code></li>
</ol>

<pre>
CAT-C/
├── catserve.py
└── credentials.json
</pre>

<hr>

<h3>4. Enable Required API</h3>

<p>
☰ Menu → APIs & Services → Library<br>
Enable:
</p>

<ul>
  <li>Google Calendar API</li>
  <li>Google Drive API (if needed)</li>
</ul>

<hr>

<h3>5. Configure Google Calendar</h3>

<ol>
  <li>Open Google Calendar</li>
  <li>Settings → Settings and sharing</li>
  <li>Add the service account email</li>
  <li>Grant <b>Make changes</b> permission</li>
</ol>

<hr>

<h2>SERVER SIDE & SCRIPT SIDE</h2>


<pre>
pip3 install flask
</pre>


<h3>First Of All Install Dependencies Of Python In Target Machine</h3>

<pre>
pip3 install google-auth google-api-python-client
</pre>



<h3>1. Modify catserve.py</h3>

<pre>
CALENDAR_EMAIL = "YOUR_EMAIL_FROM_GOOGLE_CONSOLE"
</pre>

<hr>

<h3>2. Generate Obfuscated Address</h3>

<pre>
python3 genaddr.py &lt;C2_SERVER_ADDRESS&gt;
</pre>

<p>Paste output into <code>Catc.py</code></p>

<hr>

<h3>3. Start Server</h3>

<pre>
python3 catserve.py
</pre>

<hr>

<h3>4. Run Client</h3>

<p>Run <code>Catc.py</code> on:</p>

<ul>
  <li>Windows</li>
  <li>Linux</li>
  <li>macOS</li>
</ul>

<hr>

<h3>5. Open Google Calendar</h3>

<p>
Target hooked.<br>
Command & Control active via Calendar.
</p>

</div>


### ✅ Done




## 📊 **WORKFLOW**
<img width="1000" height="560" alt="workflow" src="https://github.com/user-attachments/assets/95a21f69-6feb-4bb4-80fb-63490ce225a9" />


## 📸 **SCREENSHOTS**
<img width="1920" height="724" alt="res0" src="https://github.com/user-attachments/assets/89d04be5-2f42-46c8-a98f-8e655c51f78f" />
<img width="1920" height="693" alt="res1" src="https://github.com/user-attachments/assets/34a63231-f2ff-495a-9e29-26a49fdc472b" />

## **TESTS**
WHAT YOU GET THE AS WHEN YOU SEE NETWORK STATUS : <img width="725" height="63" alt="Image" src="https://github.com/user-attachments/assets/a668feda-5326-4b19-85f4-5581d1011492" />
<img width="805" height="641" alt="image" src="https://github.com/user-attachments/assets/819cd8c5-87b2-456d-863a-5b59e800c019" />

✅ ONLY GOOGLE SERVER CONNECTIONS (142.250.4.95)
✅ NO DIRECT TEAMSERVER / REVERSE SHELL 
✅ Port 18385: Calendar polling (hidden)
✅ AV/EDR sees: Legit Google Calendar sync

<h2>APT41 — Google Calendar C2 Resources</h2>

<p>
  This page collects reliable open-source reports on the APT41 threat group, 
  focusing on how they abused Google Calendar as a covert Command & Control (C2) channel. 
  These resources are useful for defensive research, threat intelligence, and learning about modern cloud-based attack techniques.
</p>

<ul>
  <li>
    <a href="https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics" target="_blank">
      Google TAG: APT41 Innovative Tactics
    </a>
  </li>

  <li>
    <a href="https://www.resecurity.com/blog/article/apt-41-threat-intelligence-report-and-malware-analysis" target="_blank">
      Resecurity: APT41 Malware Analysis
    </a>
  </li>

  <li>
    <a href="https://cybernews.com/security/chinese-hackers-abuse-google-calendar-for-malware-control/" target="_blank">
      Cybernews: Google Calendar Abuse
    </a>
  </li>

  <li>
    <a href="https://securityonline.info/apt41-uses-google-calendar-as-covert-c2-in-stealthy-cyberespionage-campaign/" target="_blank">
      SecurityOnline: Calendar C2 Deep Dive
    </a>
  </li>

  <li>
    <a href="https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf" target="_blank">
      Mandiant APT41 Report (PDF)
    </a>
  </li>
</ul>




▶️ <a href="https://github.com/user-attachments/assets/f1df0790-6dc0-4f95-9869-296467f71979" target="_blank">POC</a>
<div align="center">


# 📚 **CAT-C**
**Google Calendar C2 Research Platform**  
*Authorized Defensive Security Learning Only*
<div align="center">

<img width="320" height="240" alt="FBI Open Up" src="https://media.tenor.com/_YqdfwYLiQ4AAAAM/traffic-fbi-open-up.gif" />
</div>

<div style="background: linear-gradient(90deg, #ff9a9e 0%, #fecfef 50%, #fecfef 100%); 
            padding: 15px; border-radius: 12px; border-left: 5px solid #ff4757;">
  
**⚠️ EDUCATIONAL & RESEARCH USE ONLY**  
**Authorized Penetration Testing Environments**
</div>

</div>


**CAT-C Calendar C2 Agent**  
*29 OpSec Layers | GCR-RAT Protocol | Python/Linux/macOS/Windows*

</div>
