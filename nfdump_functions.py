
def differentiator_check(flow_1, flow_2, differentiators, i):

    # print(differentiators[i])
    # print(flow_1["dst4_addr"])
    # print("BEFORE X")

    x = differentiators[i]
    if flow_1[x] == flow_2[x]:

        # recurse as long as i is within the bounds of differentiators
        if i < len(differentiators) - 1:
            i = i + 1
            guard = differentiator_check(flow_1, flow_2, differentiators, i)

        else:
            guard = True

        if guard:
            return True


def create_list(flows, differentiators):

    differentiated_flows = []

    for flow in flows:
        # populate the first cell
        if not differentiated_flows:
            differentiated_flows.append(add_new_IP_values(flow, flow))
        destination_IP = flow["dst4_addr"]
        destination_IP_guard = True
        differentiation_guard = True

        # if the destination_IP already exists in flow_per_IP
        for differentiated_flow in differentiated_flows:
            if destination_IP == differentiated_flow["dst4_addr"]:
                destination_IP_guard = False
                differentiation_check = differentiator_check(differentiated_flow, flow, differentiators, 0)
                # print("after differentiation check")
                
                # if all the differentiators are matching
                if differentiation_check:
                    differentiation_guard = False
                    differentiated_flow = update_IP_values(differentiated_flow, flow)
        if destination_IP_guard or differentiation_guard:
            differentiated_flows.append(add_new_IP_values(flow, flow))

    return differentiated_flows

# def create_dicts(flows, differentiators):

#     flows_per_IP = {}
#     # flows_per_IP_protocol = {}
#     # flows_per_IP_protocol_port = {}

#     for flow in flows:

#         destination_IP = flow["dst4_addr"]

#         # not all entries have a destination port
#         try:
#             destination_port = flow["dst_port"]
#         except:
#             # print(counter)
#             destination_port = "no destination port"
            
#         protocol = flow["proto"]

#         # if the destination_IP already exists in flow_per_IP
#         if destination_IP in flows_per_IP:
#             flows_per_IP[destination_IP] = update_IP_values(flows_per_IP[destination_IP], flow)

#             # if the protocol used already exists in
#             if protocol in flows_per_IP[destination_IP]:
#                 0==0


#         # else, if the destination_IP is not present in flows_per_IP
#         # create the value and add it
#         else:
#             # do not take into account flows with no traffic
#             if flow["in_packets"] != 0 and flow["in_bytes"] != 0:
#                 # initialize the dictionary of the new IP
#                 flows_per_IP[destination_IP] = {}

#                 flows_per_IP[destination_IP] = add_new_IP_values(flows_per_IP[destination_IP], flow)

        

#     # flows = [flows_per_IP, flows_per_IP_protocol, flows_per_IP_protocol_port]
#     return flows

# get all the necessary elements from the parsed_flow
# pass them on to the new_flow
def add_new_IP_values(new_flow, parsed_flow):

    new_flow["dst4_addr"] = parsed_flow["dst4_addr"]

    new_flow["in_packets"] = parsed_flow["in_packets"]

    new_flow["in_bytes"] = parsed_flow["in_bytes"]

    new_flow["total_duration"] = calculate_duration(parsed_flow)

    # count the total number of flows for this IP address destination
    # this is used for metric calculations (take the average time instead of aggregating
    # into a single variable)
    new_flow["total_flows"] = 1
    
    new_flow["proto"] = str(parsed_flow["proto"])

    # not all entrries have a destination port
    try:
        new_flow["dst_port"] = str(parsed_flow["dst_port"])
    except:
        new_flow["dst_port"] = "no destination port"
    # print(new_flow)

    return new_flow

# update the values based on the new flow found for this IP
def update_IP_values(new_flow, parsed_flow):

    new_flow["in_packets"] = new_flow["in_packets"] + parsed_flow["in_packets"]

    new_flow["in_bytes"] = new_flow["in_bytes"] + parsed_flow["in_bytes"]

    parsed_flow_duration = calculate_duration(parsed_flow)

    new_flow["total_duration"] = new_flow["total_duration"] + parsed_flow_duration

    new_flow["total_flows"] = new_flow["total_flows"] + 1

    # print(new_flow)

    return new_flow

# calculate pps and bps based on time duration
def calculate_metrics(flow):

    # print(flow)

    flow["pps"] = int(flow["in_packets"] / (flow["total_duration"] / flow["total_flows"]))

    flow["bps"] = int(flow["in_bytes"] / (flow["total_duration"] / flow["total_flows"]))

    return flow

# calculate the duration of a flow, add that duration
# to the total duration of the flow per IP
def calculate_duration(flow):
    from datetime import datetime

    # Define the date format
    date_format = "%Y-%m-%dT%H:%M:%S.%f"

    if "t_first" in flow and "t_last" in flow:
        t_first = datetime.strptime(flow["t_first"], date_format)
        t_last = datetime.strptime(flow["t_last"], date_format)
    elif "first" in flow and "last" in flow:
        t_first = datetime.strptime(flow["first"], date_format)
        t_last = datetime.strptime(flow["last"], date_format)

    duration = abs(t_last - t_first)

    # return the duration in seconds
    return duration.total_seconds()