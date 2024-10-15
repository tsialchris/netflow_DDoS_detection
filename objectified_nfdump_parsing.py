
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


top_flows_bps = netflow_flows.get_top_IP_flows(X_bps, "bps")




# print_top_list(top_flows_bps, "bps")
# print_top_list(top_flows_pps, "pps")
# print_top_list(top_flows_UDP, "bps")
# print_top_list(top_flows_UDP, "pps")

# # print_over_threshold_list(flows_over_threshold, "bps")
# # print_over_threshold_list(flows_over_threshold, "pps")
# print_over_threshold_list(UDP_flows_over_threshold, "bps")
# print_over_threshold_list(UDP_flows_over_threshold, "pps")
