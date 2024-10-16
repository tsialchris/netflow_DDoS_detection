
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
    0==0
    with open(reading_file_location, "r") as file:
        flows = json.load(file)
else:
    print("No nfcapd_latest.json file found, exiting...")
    exit

netflow_flows = netflows()

for flow in flows:
    netflow_flows.add_flow(flow)

netflow_flows.calculate_metrics()



# amount of top flows in terms of bps
X_bps = 10

# amount of top flows in terms of pps
X_pps = 10

# amount of top flows in UDP
X_UDP = 10

# amount of top flows in DNS
X_DNS = 10


top_flows_bps = netflow_flows.get_top_IP_flows(X_bps, "bps")

top_flows_pps = netflow_flows.get_top_IP_flows(X_pps, "pps")

top_flows_UDP_bps = netflow_flows.get_top_protocol_flows(X_UDP, "bps", "17")

top_flows_UDP_pps = netflow_flows.get_top_protocol_flows(X_UDP, "pps", "17")

top_flows_DNS_bps = netflow_flows.get_top_port_flows(X_DNS, "bps", "17", "53")

top_flows_DNS_pps = netflow_flows.get_top_port_flows(X_DNS, "pps", "17", "53")



# # print_over_threshold_list(flows_over_threshold, "bps")
# # print_over_threshold_list(flows_over_threshold, "pps")
# print_over_threshold_list(UDP_flows_over_threshold, "bps")
# print_over_threshold_list(UDP_flows_over_threshold, "pps")


# TO DO:
# Implement the get_top_port_flows function
# THRESHOLDS after that

