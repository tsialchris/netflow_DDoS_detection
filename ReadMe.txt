==================In-house DoS Detection==================

This project's aim is to collect flows from .json files and output:

1. Logs and alerts for flows over specified thresholds
in packets per second (pps) or bits per second (bps)
(defined in config.json)
2. Top-n flows for specified misuse cases
(defined in config.json)

The misuse cases include:
- total_traffic
- total_DNS
- total_ICMP
- DNS_amplification
- TCP_IP_fragments
- UDP_IP_fragments
- SNMP_amplification
...

==========================================================