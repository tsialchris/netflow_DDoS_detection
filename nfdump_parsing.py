
import os
import json
from nfdump_functions import add_new_IP_values
from nfdump_functions import update_IP_values
from nfdump_functions import calculate_metrics
from list_functions import find_and_insert

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


# initialize flows_per_IP as a dictionary

flows_per_IP = {}


for flow in flows:
    destination_IP = flow["dst4_addr"]

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


# in the end, calculate the pps and bps
# in parallel keep track of their top X to avoid reparsing the list

top_flows_bps = []
top_flows_pps = []

# amount of top flows in terms of bps
X_bps = 10

# amount of top flows in terms of pps
X_pps = 10

# print(len(flows_per_IP))

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
            top_flows_bps = find_and_insert(top_flows_bps, "bps", flows_per_IP[destination_IP], "append")

        else:
            top_flows_bps = find_and_insert(top_flows_bps, "bps", flows_per_IP[destination_IP], "overwrite")

        if len(top_flows_pps) < X_pps:
            top_flows_pps = find_and_insert(top_flows_pps, "pps", flows_per_IP[destination_IP], "append")

        else:
            top_flows_pps = find_and_insert(top_flows_pps, "pps", flows_per_IP[destination_IP], "overwrite")

        # print(len(top_flows_bps))

print(len(top_flows_bps))
print(len(top_flows_pps))


# TO DO:
# fix the top_flows_bps and top_flows_pps tables to include ip addresses
# -> include them as an element in each flow (that's what I am about to do)

print(top_flows_bps)
print(top_flows_pps)






