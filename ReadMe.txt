==================In-house DoS Detection==================

This project's aim is to collect flows from .json files and output:

1. Logs and alerts for flows over specified thresholds per misuse
case in packets per second (pps) or bits per second (bps)
(thresholds defined in config.json)
2. Top-n flows for pre-specified misuse cases
(n-amount defined in config.json)

The misuse cases include:
- total_traffic
- total_DNS
- total_ICMP
- DNS_amplification
- TCP_IP_fragments
- UDP_IP_fragments
- SNMP_amplification
...

To run:
objectified_nfdump_parsing.py

- Printing can be turned on/off by commenting/uncommenting
the correct categories in the main script
(objectified_nfdump_parsing.py)

Output:
output.log

==========================================================
Post log processing is also done to produce alerts based on
the output of the objectified_nfdump_parsing.py script.

For post log processing, run:
log_monitoring.py

Output:
alerts.log

==========================================================