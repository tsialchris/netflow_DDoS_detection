
# SEND NOTIFICATIONS IN THE list_functions.py

import os
import json

from netflow_objects import netflows

from misuse_objects import total_traffic

from misuse_objects import total_UDP_traffic

from misuse_objects import total_TCP_no_flags

from misuse_objects import TCP_only_RST

from misuse_objects import TCP_only_SYN

from misuse_objects import TCP_only_FIN

from misuse_objects import total_DNS

from misuse_objects import total_X_port_destination

from misuse_objects import total_X_port_source

from misuse_objects import total_ICMP

from misuse_objects import chargen_amplification

from misuse_objects import CLDAP_amplification

from misuse_objects import DNS_amplification

from misuse_objects import TCP_IP_fragments

from misuse_objects import UDP_IP_fragments

from misuse_objects import IPv4_protocol_0

from misuse_objects import mDNS_reflection_amplification

from misuse_objects import memcached_amplification

from misuse_objects import MS_SQL_RS_amplification

from misuse_objects import netbios_reflection_amplification_1

from misuse_objects import netbios_reflection_amplification_2

from misuse_objects import RIPv1_reflection_amplification

from misuse_objects import rpcbind_reflection_amplification

from misuse_objects import SNMP_amplification_1

from misuse_objects import SNMP_amplification_2

from misuse_objects import SSDP_amplification

from misuse_objects import NTP_amplification


# f = open("./output.log", "a")
# f.write("==================================================================================================================\n")
# f.close()

# read the json file with all the flows
# store them in "flows" as json objects
# the format is [flow1, flow2, flow3, ...]
# to parse, iterate through the table "flows"
# each index is a dictionary

# reading_file_location = "./nfcapd_latest.json"

# icmp-src53.json "./syn_1.json"

# reading_file_location = "./icmp-src53.json"

reading_file_location = "./frag.json"

if os.path.isfile(reading_file_location):
    with open(reading_file_location, "r") as file:
        flows = json.load(file)
else:
    print("No nfcapd_latest.json file found, exiting...")
    exit

netflow_flows = netflows()

for flow in flows:
    netflow_flows.add_flow(flow)

netflow_flows.calculate_metrics()


# read the config file to get the thresholds and number of top flows per category
reading_file_location = "./config.json"

if os.path.isfile(reading_file_location):
    with open(reading_file_location, "r") as file:
        config = json.load(file)
else:
    print("No nfcapd_latest.json file found, exiting...")
    exit

# amount of top flows in terms of bps
amount_top_flows_IP_bps = config["amount_top_flows_IP_bps"]

# amount of top flows in terms of pps
amount_top_flows_IP_pps = config["amount_top_flows_IP_pps"]

# amount of top flows in UDP
amount_top_flows_UDP = config["amount_top_flows_UDP"]

# amount of top flows in TCP
amount_top_flows_TCP = config["amount_top_flows_TCP_no_flags"]
amount_top_flows_TCP_RST = config["amount_top_flows_TCP_RST"]
amount_top_flows_TCP_SYN = config["amount_top_flows_TCP_SYN"]
amount_top_flows_TCP_FIN = config["amount_top_flows_TCP_FIN"]

# amount of top flows in DNS
amount_top_flows_DNS = config["amount_top_flows_DNS"]

# amount of top flows in ICMP
amount_top_flows_ICMP = config["amount_top_flows_ICMP"]

# chargen amplification
amount_top_flows_chargen_amplification = config["amount_top_flows_chargen_amplification"]

# CLDAP amplification
amount_top_flows_CLDAP_amplification = config["amount_top_flows_CLDAP_amplification"]

# DNS amplification
amount_top_flows_DNS_amplification = config["amount_top_flows_DNS_amplification"]

# TCP IP fragments
amount_top_flows_TCP_IP_fragments = config["amount_top_flows_TCP_IP_fragments"]

# UDP IP fragments
amount_top_flows_UDP_IP_fragments = config["amount_top_flows_UDP_IP_fragments"]

# IPv4_protocol_0
amount_top_flows_IPv4_protocol_0 = config["amount_top_flows_IPv4_protocol_0"]

# mDNS_reflection_amplification
amount_top_flows_mDNS_reflection_amplification = config["amount_top_flows_mDNS_reflection_amplification"]

# memcached_amplification
amount_top_flows_memcached_amplification = config["amount_top_flows_memcached_amplification"]

# MS_SQL_RS_amplification
amount_top_flows_MS_SQL_RS_amplification = config["amount_top_flows_MS_SQL_RS_amplification"]

# netbios_reflection_amplification
amount_top_flows_netbios_reflection_amplification = config["amount_top_flows_netbios_reflection_amplification"]

# RIPv1_reflection_amplification
amount_top_flows_RIPv1_reflection_amplification = config["amount_top_flows_RIPv1_reflection_amplification"]

# rpcbind_reflection_amplification
amount_top_flows_rpcbind_reflection_amplification = config["amount_top_flows_rpcbind_reflection_amplification"]

# SNMP_amplification
amount_top_flows_SNMP_amplification = config["amount_top_flows_SNMP_amplification"]

# SSDP_amplification
amount_top_flows_SSDP_amplification = config["amount_top_flows_SSDP_amplification"]

# NTP_amplification
amount_top_flows_NTP_amplification = config["amount_top_flows_NTP_amplification"]

general_IP_traffic_bps_threshold = config["general_IP_traffic_bps_threshold"]
general_IP_traffic_pps_threshold = config["general_IP_traffic_pps_threshold"]

general_UDP_traffic_bps_threshold = config["general_UDP_traffic_bps_threshold"]
general_UDP_traffic_pps_threshold = config["general_UDP_traffic_pps_threshold"]

no_flags_TCP_traffic_bps_threshold = config["no_flags_TCP_traffic_bps_threshold"]
no_flags_TCP_traffic_pps_threshold = config["no_flags_TCP_traffic_bps_threshold"]

TCP_RST_traffic_bps_threshold = config["TCP_RST_traffic_bps_threshold"]
TCP_RST_traffic_pps_threshold = config["TCP_RST_traffic_pps_threshold"]

TCP_SYN_traffic_bps_threshold = config["TCP_SYN_traffic_bps_threshold"]
TCP_SYN_traffic_pps_threshold = config["TCP_SYN_traffic_pps_threshold"]

TCP_FIN_traffic_bps_threshold = config["TCP_FIN_traffic_bps_threshold"]
TCP_FIN_traffic_pps_threshold = config["TCP_FIN_traffic_pps_threshold"]

UDP_DNS_traffic_bps_threshold = config["UDP_DNS_traffic_bps_threshold"]
UDP_DNS_traffic_pps_threshold = config["UDP_DNS_traffic_pps_threshold"]

ICMP_traffic_bps_threshold = config["ICMP_traffic_bps_threshold"]
ICMP_traffic_pps_threshold = config["ICMP_traffic_pps_threshold"]

chargen_amplification_traffic_bps_threshold = config["chargen_amplification_traffic_bps_threshold"]
chargen_amplification_traffic_pps_threshold = config["chargen_amplification_traffic_pps_threshold"]

CLDAP_amplification_traffic_bps_threshold = config["CLDAP_amplification_traffic_bps_threshold"]
CLDAP_amplification_traffic_pps_threshold = config["CLDAP_amplification_traffic_pps_threshold"]

DNS_amplification_traffic_bps_threshold = config["DNS_amplification_traffic_bps_threshold"]
DNS_amplification_traffic_pps_threshold = config["DNS_amplification_traffic_pps_threshold"]

TCP_IP_fragments_traffic_bps_threshold = config["TCP_IP_fragments_traffic_bps_threshold"]
TCP_IP_fragments_traffic_pps_threshold = config["TCP_IP_fragments_traffic_pps_threshold"]

UDP_IP_fragments_traffic_bps_threshold = config["UDP_IP_fragments_traffic_bps_threshold"]
UDP_IP_fragments_traffic_pps_threshold = config["UDP_IP_fragments_traffic_pps_threshold"]

IPv4_protocol_0_traffic_bps_threshold = config["IPv4_protocol_0_traffic_bps_threshold"]
IPv4_protocol_0_traffic_pps_threshold = config["IPv4_protocol_0_traffic_pps_threshold"]

mDNS_reflection_amplification_traffic_bps_threshold = config["mDNS_reflection_amplification_traffic_bps_threshold"]
mDNS_reflection_amplification_traffic_pps_threshold = config["mDNS_reflection_amplification_traffic_pps_threshold"]

memcached_amplification_traffic_bps_threshold = config["memcached_amplification_traffic_bps_threshold"]
memcached_amplification_traffic_pps_threshold = config["memcached_amplification_traffic_pps_threshold"]

MS_SQL_RS_amplification_traffic_bps_threshold = config["MS_SQL_RS_amplification_traffic_bps_threshold"]
MS_SQL_RS_amplification_traffic_pps_threshold = config["MS_SQL_RS_amplification_traffic_pps_threshold"]

netbios_reflection_amplification_traffic_bps_threshold = config["netbios_reflection_amplification_traffic_bps_threshold"]
netbios_reflection_amplification_traffic_pps_threshold = config["netbios_reflection_amplification_traffic_pps_threshold"]

RIPv1_reflection_amplification_traffic_bps_threshold = config["RIPv1_reflection_amplification_traffic_bps_threshold"]
RIPv1_reflection_amplification_traffic_pps_threshold = config["RIPv1_reflection_amplification_traffic_pps_threshold"]

rpcbind_reflection_amplification_traffic_bps_threshold = config["rpcbind_reflection_amplification_traffic_bps_threshold"]
rpcbind_reflection_amplification_traffic_pps_threshold = config["rpcbind_reflection_amplification_traffic_pps_threshold"]

SNMP_amplification_traffic_bps_threshold = config["SNMP_amplification_traffic_bps_threshold"]
SNMP_amplification_traffic_pps_threshold = config["SNMP_amplification_traffic_pps_threshold"]

SSDP_amplification_traffic_bps_threshold = config["SSDP_amplification_traffic_bps_threshold"]
SSDP_amplification_traffic_pps_threshold = config["SSDP_amplification_traffic_pps_threshold"]

NTP_amplification_traffic_bps_threshold = config["NTP_amplification_traffic_bps_threshold"]
NTP_amplification_traffic_pps_threshold = config["NTP_amplification_traffic_pps_threshold"]

# AGGREGATE FLOWS is 2 index list that contains [TOP_LIST, THRESHOLD_DICTIONARY]
# TOP FLOWS are stored as lists, runtime might suffer for extreme cases

# aggregate_top_flows_IP_bps = get_threshold_and_top_IP_flows(netflow_flows, amount_top_flows_IP_bps, "bps", general_IP_traffic_bps_threshold, True, True)
# aggregate_top_flows_IP_pps = get_threshold_and_top_IP_flows(netflow_flows, amount_top_flows_IP_pps, "pps", general_IP_traffic_pps_threshold, True, True)

aggregate_top_flows_IP_bps = total_traffic(netflow_flows, amount_top_flows_IP_bps, "bps", general_IP_traffic_bps_threshold)
aggregate_top_flows_IP_pps = total_traffic(netflow_flows, amount_top_flows_IP_pps, "pps", general_IP_traffic_pps_threshold)

aggregate_top_flows_UDP_bps = total_UDP_traffic(netflow_flows, amount_top_flows_UDP, "bps", general_UDP_traffic_bps_threshold)
aggregate_top_flows_UDP_pps = total_UDP_traffic(netflow_flows, amount_top_flows_UDP, "pps", general_UDP_traffic_pps_threshold)

aggregate_top_flows_TCP_bps = total_TCP_no_flags(netflow_flows, amount_top_flows_TCP, "bps", no_flags_TCP_traffic_bps_threshold)
aggregate_top_flows_TCP_pps = total_TCP_no_flags(netflow_flows, amount_top_flows_TCP, "pps", no_flags_TCP_traffic_pps_threshold)

aggregate_top_flows_TCP_RST_bps = TCP_only_RST(netflow_flows, amount_top_flows_TCP_RST, "bps", TCP_RST_traffic_bps_threshold)
aggregate_top_flows_TCP_RST_pps = TCP_only_RST(netflow_flows, amount_top_flows_TCP_RST, "pps", TCP_RST_traffic_pps_threshold)

aggregate_top_flows_TCP_SYN_bps = TCP_only_SYN(netflow_flows, amount_top_flows_TCP_SYN, "bps", TCP_SYN_traffic_bps_threshold)
aggregate_top_flows_TCP_SYN_pps = TCP_only_SYN(netflow_flows, amount_top_flows_TCP_SYN, "pps", TCP_SYN_traffic_pps_threshold)

aggregate_top_flows_TCP_FIN_bps = TCP_only_FIN(netflow_flows, amount_top_flows_TCP_FIN, "bps", TCP_FIN_traffic_bps_threshold)
aggregate_top_flows_TCP_FIN_pps = TCP_only_FIN(netflow_flows, amount_top_flows_TCP_FIN, "pps", TCP_FIN_traffic_pps_threshold)

aggregate_top_flows_DNS_bps = total_DNS(netflow_flows, amount_top_flows_DNS, "bps", UDP_DNS_traffic_bps_threshold)
aggregate_top_flows_DNS_pps = total_DNS(netflow_flows, amount_top_flows_DNS, "pps", UDP_DNS_traffic_pps_threshold)
 
aggregate_top_flows_ICMP_bps = total_ICMP(netflow_flows, amount_top_flows_ICMP, "bps", ICMP_traffic_bps_threshold)
aggregate_top_flows_ICMP_pps = total_ICMP(netflow_flows, amount_top_flows_ICMP, "pps", ICMP_traffic_pps_threshold)

aggregate_top_flows_chargen_amplification_bps = chargen_amplification(netflow_flows, amount_top_flows_chargen_amplification, "bps", chargen_amplification_traffic_bps_threshold)
aggregate_top_flows_chargen_amplification_pps = chargen_amplification(netflow_flows, amount_top_flows_chargen_amplification, "pps", chargen_amplification_traffic_pps_threshold)

aggregate_top_flows_CLDAP_amplification_bps = CLDAP_amplification(netflow_flows, amount_top_flows_CLDAP_amplification, "bps", CLDAP_amplification_traffic_bps_threshold)
aggregate_top_flows_CLDAP_amplification_pps = CLDAP_amplification(netflow_flows, amount_top_flows_CLDAP_amplification, "pps", CLDAP_amplification_traffic_pps_threshold)

aggregate_top_flows_DNS_amplification_bps = DNS_amplification(netflow_flows, amount_top_flows_DNS_amplification, "bps", DNS_amplification_traffic_bps_threshold)
aggregate_top_flows_DNS_amplification_pps = DNS_amplification(netflow_flows, amount_top_flows_DNS_amplification, "pps", DNS_amplification_traffic_pps_threshold)

aggregate_top_flows_TCP_IP_fragments_bps = TCP_IP_fragments(netflow_flows, amount_top_flows_TCP_IP_fragments, "bps", TCP_IP_fragments_traffic_bps_threshold)
aggregate_top_flows_TCP_IP_fragments_pps = TCP_IP_fragments(netflow_flows, amount_top_flows_TCP_IP_fragments, "pps", TCP_IP_fragments_traffic_pps_threshold)

aggregate_top_flows_UDP_IP_fragments_bps = UDP_IP_fragments(netflow_flows, amount_top_flows_UDP_IP_fragments, "bps", UDP_IP_fragments_traffic_bps_threshold)
aggregate_top_flows_UDP_IP_fragments_pps = UDP_IP_fragments(netflow_flows, amount_top_flows_UDP_IP_fragments, "pps", UDP_IP_fragments_traffic_pps_threshold)

aggregate_top_flows_IPv4_protocol_0_bps = IPv4_protocol_0(netflow_flows, amount_top_flows_IPv4_protocol_0, "bps", IPv4_protocol_0_traffic_bps_threshold)
aggregate_top_flows_IPv4_protocol_0_pps = IPv4_protocol_0(netflow_flows, amount_top_flows_IPv4_protocol_0, "pps", IPv4_protocol_0_traffic_pps_threshold)

aggregate_top_flows_mDNS_reflection_amplification_bps = mDNS_reflection_amplification(netflow_flows, amount_top_flows_mDNS_reflection_amplification, "bps", mDNS_reflection_amplification_traffic_bps_threshold)
aggregate_top_flows_mDNS_reflection_amplification_pps = mDNS_reflection_amplification(netflow_flows, amount_top_flows_mDNS_reflection_amplification, "pps", mDNS_reflection_amplification_traffic_pps_threshold)

aggregate_top_flows_memcached_amplification_bps = memcached_amplification(netflow_flows, amount_top_flows_memcached_amplification, "bps", memcached_amplification_traffic_bps_threshold)
aggregate_top_flows_memcached_amplification_pps = memcached_amplification(netflow_flows, amount_top_flows_memcached_amplification, "pps", memcached_amplification_traffic_pps_threshold)

aggregate_top_flows_MS_SQL_RS_amplification_bps = MS_SQL_RS_amplification(netflow_flows, amount_top_flows_MS_SQL_RS_amplification, "bps", MS_SQL_RS_amplification_traffic_bps_threshold)
aggregate_top_flows_MS_SQL_RS_amplification_pps = MS_SQL_RS_amplification(netflow_flows, amount_top_flows_MS_SQL_RS_amplification, "pps", MS_SQL_RS_amplification_traffic_pps_threshold)

aggregate_top_flows_netbios_reflection_amplification_1_bps = netbios_reflection_amplification_1(netflow_flows, amount_top_flows_netbios_reflection_amplification, "bps", netbios_reflection_amplification_traffic_bps_threshold)
aggregate_top_flows_netbios_reflection_amplification_1_pps = netbios_reflection_amplification_1(netflow_flows, amount_top_flows_netbios_reflection_amplification, "pps", netbios_reflection_amplification_traffic_pps_threshold)

aggregate_top_flows_netbios_reflection_amplification_2_bps = netbios_reflection_amplification_2(netflow_flows, amount_top_flows_netbios_reflection_amplification, "bps", netbios_reflection_amplification_traffic_bps_threshold)
aggregate_top_flows_netbios_reflection_amplification_2_pps = netbios_reflection_amplification_2(netflow_flows, amount_top_flows_netbios_reflection_amplification, "pps", netbios_reflection_amplification_traffic_pps_threshold)

aggregate_top_flows_RIPv1_reflection_amplification_bps = RIPv1_reflection_amplification(netflow_flows, amount_top_flows_RIPv1_reflection_amplification, "bps", RIPv1_reflection_amplification_traffic_bps_threshold)
aggregate_top_flows_RIPv1_reflection_amplification_pps = RIPv1_reflection_amplification(netflow_flows, amount_top_flows_RIPv1_reflection_amplification, "pps", RIPv1_reflection_amplification_traffic_pps_threshold)

aggregate_top_flows_rpcbind_reflection_amplification_bps = rpcbind_reflection_amplification(netflow_flows, amount_top_flows_rpcbind_reflection_amplification, "bps", rpcbind_reflection_amplification_traffic_bps_threshold)
aggregate_top_flows_rpcbind_reflection_amplification_pps = rpcbind_reflection_amplification(netflow_flows, amount_top_flows_rpcbind_reflection_amplification, "pps", rpcbind_reflection_amplification_traffic_pps_threshold)

aggregate_top_flows_SNMP_amplification_1_bps = SNMP_amplification_1(netflow_flows, amount_top_flows_SNMP_amplification, "bps", SNMP_amplification_traffic_bps_threshold)
aggregate_top_flows_SNMP_amplification_1_pps = SNMP_amplification_1(netflow_flows, amount_top_flows_SNMP_amplification, "pps", SNMP_amplification_traffic_pps_threshold)

aggregate_top_flows_SNMP_amplification_2_bps = SNMP_amplification_2(netflow_flows, amount_top_flows_SNMP_amplification, "bps", SNMP_amplification_traffic_bps_threshold)
aggregate_top_flows_SNMP_amplification_2_pps = SNMP_amplification_2(netflow_flows, amount_top_flows_SNMP_amplification, "pps", SNMP_amplification_traffic_pps_threshold)

aggregate_top_flows_SSDP_amplification_bps = SSDP_amplification(netflow_flows, amount_top_flows_SSDP_amplification, "bps", SSDP_amplification_traffic_bps_threshold)
aggregate_top_flows_SSDP_amplification_pps = SSDP_amplification(netflow_flows, amount_top_flows_SSDP_amplification, "pps", SSDP_amplification_traffic_pps_threshold)

aggregate_top_flows_NTP_amplification_bps = NTP_amplification(netflow_flows, amount_top_flows_NTP_amplification, "bps", NTP_amplification_traffic_bps_threshold)
aggregate_top_flows_NTP_amplification_pps = NTP_amplification(netflow_flows, amount_top_flows_NTP_amplification, "pps", NTP_amplification_traffic_pps_threshold)


# ================================================REMOVE THIS IN PRODUCTION============================================ #
# aggregate_top_flows_12345_bps = total_X_port(netflow_flows, 10, "bps", 10, "6", "12345")
# aggregate_top_flows_12345_pps = total_X_port(netflow_flows, 10, "pps", 10, "6", "12345")
# ================================================REMOVE THIS IN PRODUCTION============================================ #



# THIS is how you PRINT

# netflows.print_top_flows(netflows, aggregate_top_flows_IP_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_IP_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_IP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_IP_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_UDP_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_UDP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_RST_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_RST_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_RST_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_RST_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_SYN_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_SYN_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_SYN_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_SYN_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_FIN_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_FIN_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_FIN_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_FIN_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_DNS_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_DNS_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_DNS_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_DNS_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_ICMP_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_ICMP_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_ICMP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_ICMP_bps[1], "bps")


# netflows.print_top_flows(netflows, aggregate_top_flows_chargen_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_chargen_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_chargen_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_chargen_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_CLDAP_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_CLDAP_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_CLDAP_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_CLDAP_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_DNS_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_DNS_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_DNS_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_DNS_amplification_bps[1], "bps")

netflows.print_top_flows(netflows, aggregate_top_flows_TCP_IP_fragments_pps[0], "pps")
netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_IP_fragments_pps[1], "pps")

netflows.print_top_flows(netflows, aggregate_top_flows_TCP_IP_fragments_bps[0], "bps")
netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_IP_fragments_bps[1], "bps")

netflows.print_top_flows(netflows, aggregate_top_flows_UDP_IP_fragments_pps[0], "pps")
netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_IP_fragments_pps[1], "pps")

netflows.print_top_flows(netflows, aggregate_top_flows_UDP_IP_fragments_bps[0], "bps")
netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_IP_fragments_bps[1], "bps")



# netflows.print_top_flows(netflows, aggregate_top_flows_IPv4_protocol_0_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_IPv4_protocol_0_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_IPv4_protocol_0_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_IPv4_protocol_0_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_mDNS_reflection_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_mDNS_reflection_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_mDNS_reflection_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_mDNS_reflection_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_memcached_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_memcached_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_memcached_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_memcached_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_MS_SQL_RS_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_MS_SQL_RS_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_MS_SQL_RS_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_MS_SQL_RS_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_1_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_1_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_1_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_1_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_2_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_2_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_2_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_netbios_reflection_amplification_2_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_RIPv1_reflection_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_RIPv1_reflection_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_RIPv1_reflection_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_RIPv1_reflection_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_rpcbind_reflection_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_rpcbind_reflection_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_rpcbind_reflection_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_rpcbind_reflection_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_SNMP_amplification_1_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_SNMP_amplification_1_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_SNMP_amplification_1_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_SNMP_amplification_1_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_SNMP_amplification_2_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_SNMP_amplification_2_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_SNMP_amplification_2_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_SNMP_amplification_2_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_SSDP_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_SSDP_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_SSDP_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_SSDP_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_NTP_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_NTP_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_NTP_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_NTP_amplification_bps[1], "bps")

# ================================================REMOVE THIS IN PRODUCTION============================================ #
# netflows.print_top_flows(netflows, aggregate_top_flows_12345_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_12345_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_12345_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_12345_pps[1], "pps")
# ================================================REMOVE THIS IN PRODUCTION============================================ #



# DONE create a .json config file to read the threshold values from
# JINJA templates (2.0) for .json config file
# DONE implement THRESHOLDS
# DONE add TCP flags to the netflow_port variables


# TCP flags note:
# when the protocol is not TCP, the tcp_flags variable is set to "........"
# possible values: "CE.APRSF"
# example: "...AP.SF"
# look for SYN, FIN, RST floods (where this is the only flag set)
# i.e., it is either SYN or FIN or RST not all together

# COOCKBOOK:
# ".....R.."    => only RESET flag set
# "......S."    => only SYN flag set
# ".......F"    => only FIN flag set

f = open("./output.log", "a")
f.write("==================================================END OF INTERVAL==================================================\n")
f.close()