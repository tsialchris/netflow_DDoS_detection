
import os
import json

from netflow_objects import netflows

# set the time duration of the file capture
# used to calculate the packets per second (pps)
# and bits per second (bps) metrics
time_duration = 300

# read the json file with all the flows
# store them in "flows" as json objects
# the format is [flow1, flow2, flow3, ...]
# to parse, iterate through the table "flows"
# each index is a dictionary

reading_file_location = "./nfcapd_latest.json"

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
amount_top_flows_TCP = config["amount_top_flows_TCP"]
amount_top_flows_TCP_RST = config["amount_top_flows_TCP_RST"]
amount_top_flows_TCP_SYN = config["amount_top_flows_TCP_SYN"]
amount_top_flows_TCP_FIN = config["amount_top_flows_TCP_FIN"]

# amount of top flows in DNS
amount_top_flows_DNS = config["amount_top_flows_DNS"]

general_IP_traffic_bps_threshold = config["general_IP_traffic_bps_threshold"]
general_IP_traffic_pps_threshold = config["general_IP_traffic_pps_threshold"]

general_UDP_traffic_bps_threshold = config["general_UDP_traffic_bps_threshold"]
general_UDP_traffic_pps_threshold = config["general_UDP_traffic_pps_threshold"]

general_TCP_traffic_bps_threshold = config["general_TCP_traffic_bps_threshold"]
general_TCP_traffic_pps_threshold = config["general_TCP_traffic_pps_threshold"]

TCP_RST_traffic_bps_threshold = config["TCP_RST_traffic_bps_threshold"]
TCP_RST_traffic_pps_threshold = config["TCP_RST_traffic_pps_threshold"]

TCP_SYN_traffic_bps_threshold = config["TCP_SYN_traffic_bps_threshold"]
TCP_SYN_traffic_pps_threshold = config["TCP_SYN_traffic_pps_threshold"]

TCP_FIN_traffic_bps_threshold = config["TCP_FIN_traffic_bps_threshold"]
TCP_FIN_traffic_pps_threshold = config["TCP_FIN_traffic_pps_threshold"]

UDP_DNS_traffic_bps_threshold = config["UDP_DNS_traffic_bps_threshold"]
UDP_DNS_traffic_pps_threshold = config["UDP_DNS_traffic_pps_threshold"]

# AGGREGATE FLOWS is 2 index list that contains [TOP_LIST, THRESHOLD_DICTIONARY]
# TOP FLOWS are stored as lists, runtime might suffer for extreme cases

aggregate_flows_IP_bps = netflow_flows.get_threshold_and_top_IP_flows(amount_top_flows_IP_bps, "bps", general_IP_traffic_bps_threshold, True, True)
aggregate_top_flows_IP_pps = netflow_flows.get_threshold_and_top_IP_flows(amount_top_flows_IP_pps, "pps", general_IP_traffic_pps_threshold, True, True)

aggregate_top_flows_UDP_bps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_UDP, "bps", general_UDP_traffic_bps_threshold, "17", "........", True, True)
aggregate_top_flows_UDP_pps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_UDP, "pps", general_UDP_traffic_pps_threshold, "17", "........", True, True)

aggregate_top_flows_TCP_bps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP, "bps", general_TCP_traffic_bps_threshold, "6", "........", True, True)
aggregate_top_flows_TCP_pps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP, "pps", general_TCP_traffic_pps_threshold, "6", "........", True, True)

aggregate_top_flows_TCP_RST_bps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP_RST, "bps", TCP_RST_traffic_bps_threshold, "6", ".....R..", True, True)
aggregate_top_flows_TCP_RST_pps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP_RST, "pps", TCP_RST_traffic_pps_threshold, "6", ".....R..", True, True)

aggregate_top_flows_TCP_SYN_bps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP_SYN, "bps", TCP_SYN_traffic_bps_threshold, "6", "......S.", True, True)
aggregate_top_flows_TCP_SYN_pps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP_SYN, "pps", TCP_SYN_traffic_pps_threshold, "6", "......S.", True, True)

aggregate_top_flows_TCP_FIN_bps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP_FIN, "bps", TCP_FIN_traffic_bps_threshold, "6", ".......F", True, True)
aggregate_top_flows_TCP_FIN_pps = netflow_flows.get_threshold_and_top_protocol_flows(amount_top_flows_TCP_FIN, "pps", TCP_FIN_traffic_pps_threshold, "6", ".......F", True, True)

aggregate_top_flows_DNS_bps = netflow_flows.get_threshold_and_top_port_flows(amount_top_flows_DNS, "bps", UDP_DNS_traffic_bps_threshold, "17", "53", True, True)
aggregate_top_flows_DNS_pps = netflow_flows.get_threshold_and_top_port_flows(amount_top_flows_DNS, "pps", UDP_DNS_traffic_pps_threshold, "17", "53", True, True)

# THIS is how you PRINT

# netflows.print_top_flows(netflows, aggregate_flows_IP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_flows_IP_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_UDP_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_UDP_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_RST_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_RST_bps[1], "bps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_RST_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_RST_bps[1], "bps")

netflows.print_top_flows(netflows, aggregate_top_flows_TCP_SYN_bps[0], "bps")
netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_SYN_bps[1], "bps")

netflows.print_top_flows(netflows, aggregate_top_flows_TCP_SYN_pps[0], "pps")
netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_SYN_pps[1], "pps")

# netflows.print_top_flows(netflows, aggregate_top_flows_TCP_FIN_bps[0], "bps")
# netflows.print_threshold_flows(netflows, aggregate_top_flows_TCP_FIN_bps[1], "bps")


# TO DO:
# create a .json config file to read the threshold values from
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


# TO DO:
# Check jumbo frames for core network (script-irrelevant)