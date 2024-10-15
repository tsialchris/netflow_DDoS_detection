
import os
import json
from nfdump_functions import add_new_IP_values
from nfdump_functions import update_IP_values
from nfdump_functions import calculate_metrics
from nfdump_functions import create_list

from list_functions import find_and_insert
from parsing_functions import flows_over_threshold_check
from parsing_functions import print_top_list
from parsing_functions import print_over_threshold_list

from netflow_objects import netflow_flow

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
    0==0
    with open(reading_file_location, "r") as file:
        flows = json.load(file)
else:
    print("No nfcapd_latest.json file found, exiting...")
    exit


# flows_per_IP = create_list(flows, ["dst4_addr"])
flows_per_IP_protocol = create_list(flows, ["dst4_addr", "proto"])
print("finished first list")
flows_per_IP_protocol_port = create_list(flows, ["dst4_addr", "proto", "dst_port"])
print("finished second list")

flows_per_IP = {}
# flows_per_IP_protocol = []
# flows_per_IP_protocol_port = []

# counter = 0
# create the flows_per_IP
for flow in flows:
    # counter = counter + 1
    # print(counter)
    destination_IP = flow["dst4_addr"]

    # not all entries have a destination port
    try:
        destination_port = flow["dst_port"]
    except:
        # print(counter)
        destination_port = "no destination port"
        
    protocol = flow["proto"]

    # if the destination_IP already exists in flow_per_IP
    if destination_IP in flows_per_IP:
        flows_per_IP[destination_IP] = update_IP_values(flows_per_IP[destination_IP], flow)

    # else, if the destination_IP is not present in flows_per_IP
    # create the value and add it
    else:
        # do not take into account flows with no traffic
        if flow["in_packets"] != 0 and flow["in_bytes"] != 0:
            # initialize the dictionary of the new IP
            flows_per_IP[destination_IP] = {}

            flows_per_IP[destination_IP] = add_new_IP_values(flows_per_IP[destination_IP], flow)

print("finished third list")
# in the end, calculate the pps and bps
# in parallel keep track of their top X to avoid reparsing the list

top_flows_bps = []
top_flows_pps = []
top_flows_UDP = []
top_flows_DNS = []
total_flows_over_threshold = []
UDP_flows_over_threshold = []
DNS_flows_over_threshold = []


# amount of top flows in terms of bps
X_bps = 10

# amount of top flows in terms of pps
X_pps = 10

# amount of top flows in terms of UDP
X_UDP = 10

# print(len(flows_per_IP))

# TOTAL TRAFFIC
for destination_IP in flows_per_IP:

    # if the flow is empty of traffic, remove it
    # print(flows_per_IP[destination_IP])
    if flows_per_IP[destination_IP]["in_bytes"] == 0 or flows_per_IP[destination_IP]["in_packets"] == 0:
        flows_per_IP.remove(destination_IP)
    else:
        # populate the first index of both lists
        if len(top_flows_bps) == 0 and len(top_flows_pps) == 0:
            top_flows_bps.append(flows_per_IP[destination_IP])
            top_flows_pps.append(flows_per_IP[destination_IP])

        # here, the flow["pps"] and flow["bps"] are added
        flows_per_IP[destination_IP] = calculate_metrics(flows_per_IP[destination_IP])



        if len(top_flows_bps) < X_bps:
            top_flows_bps = find_and_insert(top_flows_bps, "bps", flows_per_IP[destination_IP], "append", "protocol_irrelevant", "port_irrelevant")

        else:
            top_flows_bps = find_and_insert(top_flows_bps, "bps", flows_per_IP[destination_IP], "overwrite", "protocol_irrelevant", "port_irrelevant")

        if len(top_flows_pps) < X_pps:
            top_flows_pps = find_and_insert(top_flows_pps, "pps", flows_per_IP[destination_IP], "append", "protocol_irrelevant", "port_irrelevant")

        else:
            top_flows_pps = find_and_insert(top_flows_pps, "pps", flows_per_IP[destination_IP], "overwrite", "protocol_irrelevant", "port_irrelevant")



        total_flows_over_threshold = flows_over_threshold_check(total_flows_over_threshold, flows_per_IP[destination_IP], "protocol_irrelevant", "port_irrelevant")
        



# UDP TRAFFIC
for flow in flows_per_IP_protocol:
    if flow["in_bytes"] == 0 or flow["in_packets"] == 0:
        flows_per_IP_protocol.remove(flow)
    else:
        # populate the first index of both lists
        if len(top_flows_UDP) == 0:
            top_flows_UDP.append(flow)

        # here, the flow["pps"] and flow["bps"] are added
        flow = calculate_metrics(flow)

        # UDP protocol number == 17
        if len(top_flows_UDP) < X_UDP:
            top_flows_UDP = find_and_insert(top_flows_UDP, "pps", flow, "append", "17", "port_irrelevant")

        else:
            top_flows_UDP = find_and_insert(top_flows_UDP, "pps", flow, "overwrite", "17", "port_irrelevant")

        UDP_flows_over_threshold = flows_over_threshold_check(UDP_flows_over_threshold, flow, "17", "port_irrelevant")

# DNS TRAFFIC
for flow in flows_per_IP_protocol_port:
    if flow["in_bytes"] == 0 or flow["in_packets"] == 0:
        flows_per_IP_protocol_port.remove(flow)
    else:
        # populate the first index of both lists
        if len(top_flows_DNS) == 0 and len(top_flows_pps) == 0:
            top_flows_DNS.append(flow)

        # here, the flow["pps"] and flow["bps"] are added
        flow = calculate_metrics(flow)

        # UDP protocol number == 17
        if len(top_flows_UDP) < X_UDP:
            top_flows_UDP = find_and_insert(top_flows_UDP, "pps", flow, "append", "17", "53")

        else:
            top_flows_UDP = find_and_insert(top_flows_UDP, "pps", flow, "overwrite", "17", "53")

        UDP_flows_over_threshold = flows_over_threshold_check(UDP_flows_over_threshold, flow, "17", "53")



# print_top_list(top_flows_bps, "bps")
# print_top_list(top_flows_pps, "pps")
print_top_list(top_flows_UDP, "bps")
print_top_list(top_flows_UDP, "pps")

# print_over_threshold_list(flows_over_threshold, "bps")
# print_over_threshold_list(flows_over_threshold, "pps")
print_over_threshold_list(UDP_flows_over_threshold, "bps")
print_over_threshold_list(UDP_flows_over_threshold, "pps")






# TO DO:
# Find a way to remove duplicate IP entries in the top_flows tables
# This is the case because there is no check for the dst4_addr entry
# during insertion (it is only done based on the value of the metric - bps/pps)
# SOLUTION: it was the indexing in the insert functions (while j > index)

# TO DO:
# Along with top N per metric, save all above thresholds
# Total UDP and UDP 53 (DNS)
# TCP Flag (SYN)

# Need to create a new dictionary, flows per destination IP is not enough
# Need:
# - Flows per destination IP:protocol           to track UDP
# - Flows per destination IP:protocol:port      to track DNS