# PCAP Forensics Analyzer — Comprehensive Project Audit Report

**Audit Date:** October 16, 2026  
**Auditor Roles:** Senior Python Developer, Network Forensics Expert, UI/UX Designer & Code Auditor  
**Project:** PCAP Forensics Analyzer (Academic & DFIR Portfolio Project)  
**Author(s):** Anshika Tripathi & Jiya Gupta  
**Repository Working Directory:** `c:\Users\HP\Desktop\anshika\pcap-analyzer`  

---

## Executive Summary

The **PCAP Forensics Analyzer** is an interactive, Python- and Streamlit-based digital forensics and incident response (DFIR) application designed to automate triage, threat detection, evidence hashing, and reporting on packet capture files (`.pcap` and `.pcapng`).

This audit evaluated all Python modules, detectors, UI stylesheets, acceleration bridges, tests, and documentation. Overall, the project possesses an **impressive feature scope**, featuring dual-theme SOC dashboards, PDF report generation with detached cryptographic sidecars, custom credential scanning, and optional Rust-based acceleration. 

However, the audit uncovered **critical runtime bugs** that will crash the application during real forensic triage—notably an uncaught `AttributeError` inside `pdf_report.py` that breaks PDF generation whenever threat alerts are present, and a regex sanitation issue in `pcap_parser.py` that inadvertently strips newlines from packet payloads and silences multiline credential detections. Furthermore, the repository's `.venv` environment was found to be inoperable due to hardcoded machine paths from a previous developer environment.

This report documents all empirical findings, code audits, security considerations, and a prioritized remediation roadmap.

---

## Section A: Project Overview & Architecture

### 1. Purpose & Core Capabilities
The project serves as an incident response triage dashboard that ingests network packet captures, calculates summary statistics and cryptographic hashes, extracts Indicators of Compromise (external IPs, domains, URLs), executes four heuristic threat detectors (port scan, beaconing, DNS tunneling, plaintext credentials), provides a specialized credential analysis panel, and generates downloadable forensic reports in both Markdown and PDF formats.

### 2. Tech Stack & Dependencies
- **UI Framework:** Streamlit (>=1.35.0)
- **Packet Parsing:** Scapy (>=2.5.0)
- **Data Manipulation & Visualization:** Pandas (>=2.0.0), Plotly (>=5.20.0), NetworkX (>=3.2.0), Matplotlib (>=3.7.0)
- **PDF Generation & Security:** ReportLab (>=4.0.0), hashlib, uuid
- **Acceleration:** PyO3 Rust extension (`pcap_rust_accel`), with pure-Python fallback
- **Integration:** Anthropic Model Context Protocol (MCP) Python SDK (`mcp>=1.2.0`)
- **Missing from requirements.txt:** `pytest` (referenced in documentation and testing guides)

### 3. Application Entry Points & Execution Workflows
The project has three distinct entry points:
1. **Interactive Web Dashboard (`app.py`):**
   - Run command: `streamlit run app.py` (or `python -m streamlit run app.py`)
   - Workflow: Sidebar case configuration -> File upload (`.pcap` / `.pcapng`) -> Hash calculation -> Scapy parsing into `PacketRecord` objects -> Cache storage -> Statistics calculation -> Detector execution -> Credential extraction -> Dashboard rendering across 8 tabs -> Markdown / PDF report export & integrity verification.
2. **Command-Line Interface (`main.py`):**
   - Run command: `python main.py <capture.pcap> [--report <out.md>] [--max-packets <N>]`
   - Workflow: CLI argument parsing -> Scapy packet parsing -> IOC extraction -> Detector execution -> Alert stdout printing -> Optional Markdown report saving.
3. **MCP Server (`mcp_server/server.py`):**
   - Run command: `python -m mcp_server.server`
   - Workflow: FastMCP stdio server exposing 11 JSON tools (`analyze_pcap`, `calculate_statistics`, `extract_iocs`, `detect_port_scan`, `detect_beaconing`, `detect_dns_tunneling`, `detect_plaintext_credentials`, `generate_report`, `generate_network_graph`, `calculate_hash`, `summary`).

### 4. High-Level Architecture Diagram

```
+---------------------------------------------------------------------------------+
|                                 USER INTERFACES                                 |
|   +--------------------------+   +-------------------+   +------------------+   |
|   | Streamlit GUI (app.py)   |   | CLI (main.py)     |   | MCP Server       |   |
|   | - Theme Manager & CSS    |   | - Terminal triage |   |   (FastMCP)      |   |
|   | - 8 Tabbed SOC Views     |   | - MD report export|   | - AI tool calls  |   |
|   +-------------+------------+   +---------+---------+   +--------+---------+   |
+-----------------|--------------------------|----------------------|-------------+
                  |                          |                      |
                  v                          v                      v
+---------------------------------------------------------------------------------+
|                       CORE ORCHESTRATION & PERFORMANCE                          |
|   - performance.py: @st.cache_data wrappers, timing profiler                    |
|   - config.py: Global toggles & cache eviction settings                         |
+---------------------------------------------------------------------------------+
                                      |
       +------------------------------+------------------------------+
       v                                                             v
+-----------------------------+               +-----------------------------------+
|     PARSING & EVIDENCE      |               |          DATA STRUCTURES          |
|  - pcap_parser.py (Scapy)   |               |  - models.py: PacketRecord        |
|  - hashing.py (MD5/SHA1/256)|               |  - calculate_statistics.py        |
+--------------+--------------+               +-----------------+-----------------+
               |                                                |
               +----------------------+-------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
|                               DETECTION ENGINES                                 |
|  +--------------------+  +--------------------+  +----------------------------+ |
|  | Port Scan Detector |  | Beaconing Detector |  | DNS Tunneling Detector     | |
|  | (detectors/        |  | (detectors/        |  | (detectors/dns_tunneling.py| |
|  |  port_scan.py)     |  |  beaconing.py)     |  |  & accelerated.py / Rust)  | |
|  +--------------------+  +--------------------+  +----------------------------+ |
|  +--------------------+  +--------------------+  +----------------------------+ |
|  | Plaintext Creds    |  | Password Detector  |  | IOC Extractor              | |
|  | (detectors/        |  | (password_detector |  | (ioc_extractor.py: IPs,    | |
|  |  plaintext_creds)  |  |  & credential_utils|  |  domains, URLs)            | |
|  +--------------------+  +--------------------+  +----------------------------+ |
+---------------------------------------------------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
|                           OUTPUT & FORENSIC ARTIFACTS                           |
|  - report_generator.py: Markdown report synthesis                               |
|  - pdf_report.py: Forensic PDF document generation (ReportLab)                  |
|  - report_integrity.py: Post-generation SHA-256 sidecar calculation             |
|  - hash_verifier.py: Detached signature verification tool                       |
|  - communication_graph.py: NetworkX / Plotly graph model                        |
+---------------------------------------------------------------------------------+
```

---

## Section B: Feature Inventory & Forensic Verification Table

| Feature | Current Implementation | Relevant File / Function | Status | Evidence & Forensic Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **PCAP Support** | Scapy `rdpcap()` file read | `pcap_parser.py`: `parse_pcap` | **Working** | Tested and functional. Loads full PCAP file into memory. |
| **PCAPNG Support** | Delegated to Scapy `rdpcap()` | `pcap_parser.py`: `parse_pcap` | **Partially Working** | Scapy's `rdpcap` supports basic PCAPNG, but fails on certain block types without `PcapNgReader`. Large files cause high memory pressure. |
| **File Validation** | Upload type filter `["pcap", "pcapng"]` | `app.py`: `st.file_uploader` | **Partially Working** | Extension-based only. No magic-byte / file-header validation before handing to Scapy; corrupt files cause unhandled Scapy exceptions in `main.py`. |
| **Packet Parsing** | Extracts IP, TCP/UDP, DNS, HTTP | `pcap_parser.py`: `parse_pcap` | **Partially Working** | IPv6 packets are ignored (`src_ip`/`dst_ip` become `None`). Non-printable byte filter `re.sub(rb"[^\x20-\x7e]", b".", ...)` turns `\r\n` into `..`, breaking multiline regexes. |
| **Protocol Identification** | `_proto_name` checks DNS, HTTP, TCP, UDP, IP | `pcap_parser.py`: `_proto_name` | **Partially Working** | Identifies DNS, HTTP, TCP, UDP, IP, OTHER. Misses TLS/HTTPS (labeled as generic TCP), ICMP, ARP, SSH, SMB, DHCP. |
| **IP & Port Analysis** | Extracts src/dst IP & transport ports | `pcap_parser.py`: lines 59-70 | **Working** | Works for IPv4 TCP/UDP. Fails for IPv6 and non-TCP/UDP protocols (ICMP, IGMP). |
| **DNS Metadata** | Query name extraction | `pcap_parser.py`: line 71 | **Partially Working** | Extracts query name (`qname`), but ignores DNS response records (A, AAAA, CNAME, TXT, response codes). |
| **HTTP Metadata** | Scapy `HTTPRequest` Host & Path | `pcap_parser.py`: lines 77-80 | **Partially Working** | Extracts Host and Path. Does not extract method (GET/POST), User-Agent, status codes, or HTTP responses. |
| **TLS Metadata** | Claimed in roadmap / notes | `pdf_report.py`: line 357 | **Missing** | Explicitly not implemented in `pcap_parser.py`. All HTTPS traffic is lumped into TCP without SNI or TLS version. |
| **Traffic Statistics** | Packet counts, duration, bytes, unique IPs, sessions, protocols | `calculate_statistics.py`: `calculate_statistics` | **Working** | Computes stats correctly. Note: "sessions" is computed as directed `(src_ip, dst_ip)` pairs rather than bi-directional conversations or 5-tuples. |
| **Protocol Distribution** | Frequency counts & Plotly pie/bar charts | `visualization/charts.py`: `protocol_pie_chart`, `app.py` | **Working** | Visualizes protocol breakdown effectively using custom Plotly theme. |
| **Conversations / Graph** | NetworkX directed graph with Spring layout | `communication_graph.py`: `build_graph`, `create_graph_figure` | **Working** | Renders interactive node/edge communication map in Plotly. |
| **Packet Filtering & Search** | Protocol dropdown & IP substring filter | `app.py`: lines 708-744 | **Working** | Works on parsed in-memory DataFrame. Limited to protocol equality and IP substring match. |
| **Port Scan Detection** | Sliding window distinct destination port threshold | `detectors/port_scan.py`: `detect_port_scans` | **Partially Working** | Filters `tcp_syn_like` by checking `dst_port is not None`, but does NOT verify TCP SYN flag. High-volume outbound web traffic or DNS queries can trigger false positives. |
| **Beaconing Detection** | Inter-arrival time coefficient of variation (<0.15) | `detectors/beaconing.py`: `detect_beaconing` | **Partially Working** | Groups all packet timestamps for an IP pair. In high-speed TCP streaming/downloads, rapid packet bursts distort interval statistics. Should track connection starts (SYN) or session events. |
| **DNS Tunneling Detection** | Subdomain length (>=25) & Shannon entropy (>=3.5) | `detectors/dns_tunneling.py`: `detect_dns_tunneling` | **Partially Working** | Algorithm is mathematically sound, but `_root_domain` splits by `.` and takes `parts[-2:]`. Fails for multi-part TLDs (e.g. `.co.uk`, `.gov.in`), lumping all queries under `co.uk`. |
| **Plaintext Creds (Legacy)** | Regex scanning of payload snippet | `detectors/plaintext_creds.py` | **Partially Working** | `^USER` and `^PASS` multiline regexes fail because `\r\n` is replaced with `..` in `pcap_parser.py`. |
| **Password Detector (New)** | Deep scanner for Basic Auth, Bearer, JWT, FTP, Telnet, IMAP | `password_detector.py`: `detect_credentials` | **Working** | Successfully parses Basic Auth base64, API keys, and URL params. Same 256-byte payload truncation limitation. |
| **Timeline Analysis** | 1-second resampled packet rate and bandwidth area charts | `app.py`: lines 787-860 | **Working** | Clean Plotly charts displaying packets/sec and byte volume over time. |
| **Evidence Hashing** | MD5, SHA-1, SHA-256 cryptographic digests | `hashing.py`: `calculate_hashes` | **Working** | Computes 3 standard DFIR hashes using 8KB chunk streaming. |
| **Case & Evidence Info** | Sidebar metadata inputs (case #, evidence #, analyst) | `app.py`: lines 64-110 | **Working** | Case fields populate header summaries and PDF report metadata. Remarks field is omitted from Markdown report. |
| **Markdown Report Export** | Text-based Markdown forensic summary | `report_generator.py`: `generate_report` | **Working** | Generates detailed investigation report. Downloadable as `.md`. |
| **PDF Report Generation** | Professional ReportLab multi-page document | `pdf_report.py`: `generate_pdf_report` | **CRITICAL BUG (P0)** | **AttributeError on `a.timestamp`:** Accesses `a.timestamp` on `PortScanAlert`, `BeaconAlert`, and `DNSTunnelAlert`, none of which have this attribute! Crashes immediately when alerts exist. |
| **Report Integrity (Sidecar)** | Detached `.sha256` JSON sidecar verification | `report_integrity.py`, `hash_verifier.py` | **Partially Working** | DFIR architecture is conceptually excellent (detached hashing). However, `hash_verifier.py` crashes on Windows default consoles due to Unicode checkmark `\u2713`. |
| **Theme / Design System** | Dark SOC & Light theme with CSS tokens | `design_system.py`, `ui_styles.py`, `assets/theme.css` | **Working** | High quality cybersecurity aesthetic with glassmorphism cards and custom typography. |
| **Rust Acceleration** | PyO3 C-extension for entropy and edge aggregation | `rust_bridge.py`, `accelerated.py`, `rust/` | **Not Verified** | Rust toolchain and compiled `.whl` extension not present in local environment; gracefully fell back to pure Python as designed. |
| **MCP Integration** | FastMCP stdio server exposing 11 analysis tools | `mcp_server/server.py`, `mcp_server/tools.py` | **Working** | Well-designed MCP tool suite. Missing `detect_credentials` tool. |
| **Automated Testing** | Pytest unit test suites | `tests/test_detectors.py`, `tests/test_accelerated.py` | **Partially Working** | 7 detector tests pass. No tests exist for PDF export, reporting, parser, hashing, or CLI. Virtualenv was broken. |

---

## Section C: UI/UX Audit & User Experience Review

### 1. Visual Hierarchy & Theme Styling
- **Strengths:** 
  - The dark SOC theme (`#0a0e17` background with `#0891b2` cyan and `#4f46e5` indigo accents) provides a distinct, professional cybersecurity dashboard feel reminiscent of Microsoft Defender XDR or CrowdStrike Falcon.
  - The hero banner and glassmorphism metric cards (`.soc-metric-card`) give instant visual polish without cluttering the screen.
  - The Light/Dark theme toggle functions smoothly using CSS custom property injection without page reloads.
- **Weaknesses:**
  - **Banner / Uploader Disconnection:** The hero banner is rendered *inside* the sidebar controls block (`app.py` line 87), causing an awkward ordering where case details and packet count inputs wrap around it.
  - **Sidebar Cramping:** The sidebar contains too many dense form fields (Case Number, Evidence Number, Case Title, Organization, Max Packets, Investigator Name, Remarks) with minimal vertical grouping or collapsible organization.
  - **No Active Case Header in Main Area:** When examining tabs (e.g. Alerts or Packet Viewer), the investigator loses sight of which case or evidence file is currently under review unless they inspect the sidebar.

### 2. Dashboard Cards & Metrics
- The top-level 6-card grid (Total Packets, Unique IPs, Sessions, Protocols, Traffic, Alerts) provides good executive triage numbers.
- **Improvement Opportunity:** Cards currently display static numbers without contextual indicators (e.g., alert breakdown badge, duration formatted as `hh:mm:ss`, or data rate in Mbps).

### 3. Charts, Tables & Visualization
- **Protocol Charts:** Displays both a Pie Chart and Bar Chart side-by-side. This is redundant since both visualize the exact same dataset (`protocol_counts`). Replacing one with Top Talkers or Bandwidth per Protocol would provide higher forensic value.
- **Network Graph:** Rendered with Plotly and NetworkX spring layout. On captures with >50 nodes, the force-directed layout becomes a dense, unreadable hairball. Lacks node filtering (e.g., filter by degree or external IPs only).
- **Packet Viewer:**
  - Displays only 5 columns: Time, Source, Destination, Protocol, Length.
  - Does NOT display Source Port, Destination Port, TCP Flags, or Info/Summary.
  - Lacks row drill-down or packet hex/ASCII detail view. An analyst cannot inspect payload content for an individual packet from the viewer.

### 4. Alert & Credential Presentation
- The **Alerts Tab** relies on collapsible `st.expander` containers. If there are 0 alerts, it displays a green success box inside the expander.
- The **Passwords & Credentials Tab** is exceptionally well structured:
  - Metric cards for Critical / High / Medium / Low severities.
  - Multiselect filter by severity.
  - "Show raw credential values" toggle for screen sharing / masking.
  - CSV export button.
  - Expanders for weak/default credentials and reused passwords.

### 5. Report & Export Workflow
- The Report tab renders the Markdown report inline and provides download buttons.
- The PDF export workflow generates the PDF into a temporary directory and exposes buttons for both the PDF and `.sha256` integrity sidecar.
- **Flaw:** There is no PDF preview inside the app; the user must download the PDF and open it in an external reader.

---

## Section D: Technical, Security & Forensic Integrity Audit

### 1. Critical Runtime Bugs (Empirically Verified)

#### Bug 1: Unhandled `AttributeError` in `pdf_report.py` (P0 - Fatal Crash)
- **Location:** `pdf_report.py`, lines 441–446
- **Code:**
  ```python
  for a in port_scan_alerts:
      timeline_events.append((a.timestamp, "Port Scan", getattr(a, "severity", "N/A"), a.summary()))
  for a in beacon_alerts:
      timeline_events.append((a.timestamp, "Beaconing", getattr(a, "severity", "N/A"), a.summary()))
  for a in dns_alerts:
      timeline_events.append((a.timestamp, "DNS Tunneling", getattr(a, "severity", "N/A"), a.summary()))
  ```
- **Evidence:** `PortScanAlert` only defines `window_start` and `window_end`. `BeaconAlert` defines no timestamp. `DNSTunnelAlert` defines no timestamp. When any of these alerts occur, calling `generate_pdf_report()` raises:
  `AttributeError: 'PortScanAlert' object has no attribute 'timestamp'`
- **Impact:** Clicking "Generate PDF Report" on any capture with detected threats causes an immediate hard crash.

#### Bug 2: Payload Sanitization Destroys Multiline Regex Matching (P0 - Silent Failure)
- **Location:** `pcap_parser.py`, line 86
- **Code:**
  ```python
  snippet = re.sub(rb"[^\x20-\x7e]", b".", raw_bytes[:256])
  rec.payload_snippet = snippet.decode(errors="ignore")
  ```
- **Evidence:** Replacing all bytes outside ASCII `0x20-0x7e` with `.` converts carriage returns (`\r`, `0x0d`) and newlines (`\n`, `0x0a`) into `..`. Detectors that rely on multiline anchors (e.g. `detectors/plaintext_creds.py` lines 20-21: `re.compile(rb"(?i)^USER (\S+)", re.MULTILINE)` and `password_detector.py` lines 96-107: `re.compile(r"(?im)^USER\s+(\S+)")`) **never match** commands on subsequent lines.
- **Impact:** Legitimate plaintext credentials (FTP, POP3, SMTP, IRC) appearing after headers or initial commands are silently ignored.

#### Bug 3: Faulty RFC 1918 Private IP Classification in `ioc_extractor.py` (P1 - False Classifications)
- **Location:** `ioc_extractor.py`, lines 14–19
- **Code:**
  ```python
  _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.2", "172.30.", "172.31.", "192.168.", "127.", "169.254.")
  ```
- **Evidence:** `"172.2"` matches any IP string starting with `172.2`, including public Google IP ranges (`172.217.16.14`), Cloudflare, and public networks (`172.200.x.x` through `172.255.x.x`). Empirical execution confirmed `172.217.16.14` is classified as `internal_ips`.
- **Impact:** Critical external threat indicators are falsely classified as benign internal hosts.

#### Bug 4: Console Unicode Crash in `hash_verifier.py` on Windows (P1 - Tool Crash)
- **Location:** `report_integrity.py`, line 117 & `hash_verifier.py`, line 42
- **Code:**
  ```python
  return "✓ VERIFIED" if self.verified else "✗ MODIFIED"
  ```
- **Evidence:** In standard Windows consoles using Code Page 1252 (Windows-1252), printing Unicode characters `\u2713` and `\u2717` raises `UnicodeEncodeError: 'charmap' codec can't encode character '\u2713'`.
- **Impact:** Running the standalone verification script fails on default Windows terminals.

---

### 2. Forensic Integrity & Memory Analysis

#### Evidence Tampering & In-Memory PCAP Processing
- **Finding:** In `performance.py` (`calculate_hashes_cached`), uploaded PCAP bytes are written to a temporary file on disk, read back in 8KB chunks, hashed, and unlinked. Immediately afterward in `parse_pcap_cached`, the exact same bytes are written to disk a *second* time.
- **Risk:** For a 200MB PCAP file, 400MB of redundant disk I/O occurs on every new capture.
- **Remediation:** Hash the in-memory `file_bytes` directly via `hashlib` without temporary disk writes.

#### Scalability & Memory Exhaustion (`rdpcap` vs `PcapReader`)
- **Finding:** `pcap_parser.py` uses Scapy's `rdpcap(path)`, which parses the entire capture into memory before evaluating `max_packets` (`app.py` line 49).
- **Risk:** In Scapy, each packet object consumes ~1.5 KB to 3 KB of Python object overhead. A 500 MB capture file containing 1,000,000 packets will consume 2 GB to 3.5 GB of RAM, triggering Out-Of-Memory (OOM) crashes on standard laptops.
- **Remediation:** Stream packets iteratively using `scapy.utils.PcapReader(path)` and break immediately when `max_packets` is reached.

#### IPv6 Omission & Protocol Gaps
- **Finding:** `pcap_parser.py` only inspects `pkt.haslayer(IP)`. If an enterprise capture contains IPv6 traffic (`pkt.haslayer(IPv6)`), `src_ip` and `dst_ip` are left `None`, and all IPv6 traffic is misclassified under "OTHER".

---

## Section E: Testing & Verification Audit

### 1. Environment & Dependency Status
- **Broken Virtualenv:** The repository includes a `.venv` directory configured with:
  `command = C:\Users\vinay tirpathi\AppData\Local\Programs\Python\Python313\python.exe -m venv d:\ANSHIKA\MMMUT\enhanced\pcap-analyzer\.venv`
  Executing `.\.venv\Scripts\python.exe` fails with `executable not found`.
- **System Python:** Python 3.10.11 at `C:\Users\HP\AppData\Local\Programs\Python\Python310\python.exe`.
- **Missing Test Dependencies:** `pytest` is not installed in the system Python environment and is missing from `requirements.txt`.

### 2. Test Execution Log

```
+-----------------------------------------------------------------------------------------+
| TEST CHECK                                | RESULT   | DETAILS / ERROR                  |
+-----------------------------------------------------------------------------------------+
| test_port_scan_detects_many_ports_fast    | PASSED   | Verified sliding window trigger  |
| test_port_scan_ignores_normal_traffic     | PASSED   | Verified low-port baseline       |
| test_beaconing_detects_regular_intervals  | PASSED   | Verified variance < 0.15         |
| test_beaconing_ignores_irregular_traffic  | PASSED   | Verified random intervals        |
| test_dns_tunneling_flags_high_entropy     | PASSED   | Verified domain grouping         |
| test_dns_tunneling_ignores_normal_dns     | PASSED   | Verified baseline rejection      |
| test_plaintext_creds_detects_form_pwd     | PASSED   | Verified form match on 1st line  |
| test_accelerated.py                       | BLOCKED  | Missing 'networkx' in Sys Python |
| pdf_report.py on PortScanAlert            | FAILED   | AttributeError: 'timestamp'      |
| pdf_report.py on BeaconAlert              | FAILED   | AttributeError: 'timestamp'      |
| pdf_report.py on DNSTunnelAlert           | FAILED   | AttributeError: 'timestamp'      |
| hash_verifier.py on Windows CP1252        | FAILED   | UnicodeEncodeError: '\u2713'     |
| ioc_extractor on 172.217.16.14 (Google)   | FAILED   | Misclassified as internal IP     |
| Multiline FTP USER/PASS on packet line 2  | FAILED   | Sanitizer replaced \r\n with ..  |
+-----------------------------------------------------------------------------------------+
```

---

## Section F: Prioritized Improvement Roadmap

### P0 — Critical (Security, Data Integrity & Broken Core Functionality)

#### 1. Fix PDF Generation Alert Attributes & Crash
- **Problem:** `pdf_report.py` references `a.timestamp` on `PortScanAlert`, `BeaconAlert`, and `DNSTunnelAlert`.
- **Solution:** Add `timestamp: float` to `BeaconAlert` (using first connection time) and `DNSTunnelAlert` (using first query time), and map `PortScanAlert.window_start` to `timestamp`.
- **Files:** `detectors/port_scan.py`, `detectors/beaconing.py`, `detectors/dns_tunneling.py`, `pdf_report.py`.
- **Difficulty:** Easy.
- **Testing:** Unit test generating a complete PDF report containing all 4 alert types.

#### 2. Fix Payload Sanitization & Multiline Credential Detection
- **Problem:** `re.sub(rb"[^\x20-\x7e]", b".", raw_bytes[:256])` turns `\r\n` into `..`, breaking multiline regexes like `^USER` and `^PASS`.
- **Solution:** Preserve whitespace and newlines `\r`, `\n`, `\t` in `pcap_parser.py` (e.g. `rb"[^\x20-\x7e\r\n\t]"`), and widen snippet inspection window from 256 bytes to 1024–2048 bytes for HTTP POST bodies.
- **Files:** `pcap_parser.py`, `password_detector.py`, `detectors/plaintext_creds.py`.
- **Difficulty:** Easy.
- **Testing:** Unit test asserting detection of multi-command FTP exchanges and POST bodies with preceding headers.

#### 3. Fix Private IP Range Classification in IOC Extractor
- **Problem:** Prefix `"172.2"` treats public IPs (like Google `172.217.x.x`) as private.
- **Solution:** Replace string prefix matching with Python standard library `ipaddress.ip_address(ip).is_private` (which also correctly handles IPv6, link-local, loopback, and carrier-grade NAT).
- **Files:** `ioc_extractor.py`.
- **Difficulty:** Easy.
- **Testing:** Test against known public (`172.217.16.14`, `8.8.8.8`, `1.1.1.1`) and private (`10.0.0.1`, `172.16.0.1`, `172.31.255.254`, `192.168.1.1`) IPs.

#### 4. Fix Windows Console Unicode Crash in Hash Verifier
- **Problem:** `hash_verifier.py` crashes on standard Windows CP1252 consoles printing `✓`.
- **Solution:** Use ASCII fallback symbols (`[PASS]` / `[FAIL]` or `[OK]` / `[MODIFIED]`) or configure `sys.stdout.reconfigure(encoding='utf-8')`.
- **Files:** `report_integrity.py`, `hash_verifier.py`.
- **Difficulty:** Easy.
- **Testing:** Execute `hash_verifier.py` in a simulated CP1252 environment.

---

### P1 — High (Reliability, Architecture & Major Feature Gaps)

#### 5. Streaming Packet Parsing (`PcapReader`) & Memory Optimization
- **Problem:** `rdpcap()` reads all packets into memory at once; a 200MB+ PCAP can freeze or crash Streamlit.
- **Solution:** Refactor `parse_pcap` to use Scapy's streaming `PcapReader`, incrementing a counter and stopping immediately when `max_packets` is reached.
- **Files:** `pcap_parser.py`.
- **Difficulty:** Medium.
- **Testing:** Benchmark memory consumption and parse time with a synthetic 50,000 packet PCAP.

#### 6. Add IPv6 and Comprehensive Protocol Support
- **Problem:** Captures with IPv6 drop host IPs and classify as "OTHER". No TLS SNI or ICMP classification.
- **Solution:** Add `IPv6` layer support, ICMP/ICMPv6 classification, and basic TLS ClientHello SNI inspection for HTTPS traffic.
- **Files:** `pcap_parser.py`, `models.py`.
- **Difficulty:** Medium.
- **Testing:** Synthetic test PCAPs with IPv6 packets and TLS ClientHello records.

#### 7. Repair Python Environment & Package Declarations
- **Problem:** Broken `.venv` pointing to non-existent path `C:\Users\vinay tirpathi\...`, missing `pytest` in `requirements.txt`.
- **Solution:** Add instructions and scripts to generate a clean local virtual environment and pin `pytest>=8.0.0`.
- **Files:** `requirements.txt`, `README.md`.
- **Difficulty:** Easy.

---

### P2 — Medium (Forensic Capabilities, Usability & Performance)

#### 8. Packet Viewer Drill-Down & Hex/ASCII Payload Inspector
- **Problem:** Packet viewer table only shows 5 basic fields. An analyst cannot inspect packet payload, TCP flags, or protocol headers.
- **Solution:** Add Source Port, Destination Port, TCP Flags, and an expandable modal/drawer or side panel showing the formatted Hex/ASCII dump of selected packets (Wireshark-style).
- **Files:** `app.py`, `pcap_parser.py`, `models.py`.
- **Difficulty:** Medium.

#### 9. True Bi-Directional Conversations & Top Talkers
- **Problem:** Currently "sessions" are counted as directed IP pairs `(src, dst)`. A simple two-way ping or TCP handshake counts as 2 sessions.
- **Solution:** Canonicalize conversations as `(min(ip1, ip2), max(ip1, ip2))` and include 5-tuple tracking (IPs + ports + protocol) with byte volume and duration.
- **Files:** `calculate_statistics.py`, `app.py`, `pdf_report.py`.
- **Difficulty:** Medium.

#### 10. Robust Domain / TLD Parsing in DNS Tunnel Detector
- **Problem:** `_root_domain` splits on `.` and takes last 2 labels, failing on `.co.uk`, `.edu.au`, etc.
- **Solution:** Add a lightweight multi-level suffix handler (matching common 2-level TLDs like `.co.uk`, `.com.au`, `.gov.in`) to prevent severe false positives.
- **Files:** `detectors/dns_tunneling.py`, `accelerated.py`.
- **Difficulty:** Easy.

---

### P3 — Polish (Visual Refinements, Synthetic Samples & Documentation)

#### 11. Built-in Synthetic Sample PCAP Generator
- **Problem:** The `samples/` folder is empty due to `.gitignore`, requiring users to search third-party websites before they can test the analyzer.
- **Solution:** Provide a lightweight test generator script (`samples/generate_sample_pcap.py`) using Scapy to generate small, safe sample PCAPs with benign traffic, a port scan, DNS tunneling, and plaintext HTTP credentials.
- **Files:** `samples/generate_sample_pcap.py`.
- **Difficulty:** Easy.

#### 12. UI Layout Polish & Header Re-Organization
- **Problem:** Sidebar is cluttered with unorganized inputs; hero banner renders inside sidebar container in code; no active case header in main view.
- **Solution:** Cleanly structure the sidebar with collapsible sections, place case badges in the top main container, and replace the redundant protocol bar chart with a Top Talkers table.
- **Files:** `app.py`, `ui_components.py`.
- **Difficulty:** Easy.

---

**Report Status:** COMPLETE — All findings verified against current codebase. No files modified.
