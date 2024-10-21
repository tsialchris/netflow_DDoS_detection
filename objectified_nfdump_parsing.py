
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



# read the json file with all the flows
# store them in "flows" as json objects
# the format is [flow1, flow2, flow3, ...]
# to parse, iterate through the table "flows"
# each index is a dictionary

reading_file_location = "./nfcapd_latest.json"

# reading_file_location = "./syn_1.json"

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


# ================================================REMOVE THIS IN PRODUCTION============================================ #
# aggregate_top_flows_12345_bps = total_X_port(netflow_flows, 10, "bps", 10, "6", "12345")
# aggregate_top_flows_12345_pps = total_X_port(netflow_flows, 10, "pps", 10, "6", "12345")
# ================================================REMOVE THIS IN PRODUCTION============================================ #



# THIS is how you PRINT

# netflows.print_top_flows(netflows, aggregate_top_flows_IP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_IP_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_IP_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_IP_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_UDP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_RST_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_RST_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_RST_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_RST_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_SYN_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_SYN_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_SYN_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_SYN_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_FIN_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_FIN_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_DNS_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_DNS_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_DNS_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_DNS_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_ICMP_bps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_ICMP_bps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_ICMP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_ICMP_bps[1], "bps")


# netflows.print_top_flows(netflows, aggregate_top_flows_chargen_amplification_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_chargen_amplification_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_chargen_amplification_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_chargen_amplification_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_IP_fragments_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_IP_fragments_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_IP_fragments_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_IP_fragments_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_UDP_IP_fragments_pps[0], "pps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_IP_fragments_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_UDP_IP_fragments_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_IP_fragments_bps[1], "bps")


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