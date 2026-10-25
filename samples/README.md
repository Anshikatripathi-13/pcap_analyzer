# Sample Captures

Real-world and investigative `.pcap`/`.pcapng` files are gitignored by default to prevent accidental exposure of sensitive, proprietary, or private network traffic.

### Synthetic Test Capture
For safe out-of-the-box evaluation and automated test suites, the repository includes a synthetic test capture:
- `samples/synthetic_investigation.pcap`: A synthetic 103-packet capture generated using `samples/generate_sample_pcap.py`. It contains simulated port scanning, C2 beaconing, DNS tunneling, and plaintext credential scenarios using strictly RFC 1918 private IP addresses and RFC 5737 documentation test addresses (`198.51.100.0/24`, `203.0.113.0/24`). No real-world evidence or private user data is present.

To regenerate or customize the synthetic capture:
```bash
python samples/generate_sample_pcap.py
```

### External Forensic Samples
To test the analyzer with external malware or protocol captures, you can download public forensic datasets:
- https://www.malware-traffic-analysis.net/ — real malware traffic captures with write-ups (ideal for testing beaconing and DNS tunneling detectors)
- https://wiki.wireshark.org/SampleCaptures — general protocol sample captures
- Or generate your own locally: `tcpdump -i eth0 -w samples/test.pcap`

Drop any `.pcap`/`.pcapng` file into this directory and run:
```bash
python main.py samples/your_capture.pcap --report reports/report.md
```
