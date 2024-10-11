
# get all the necessary elements from the parsed_flow
# pass them on to the new_flow
def add_new_IP_values(new_flow, parsed_flow):

    new_flow["in_packets"] = parsed_flow["in_packets"]

    new_flow["in_bytes"] = parsed_flow["in_bytes"]

    new_flow["total_duration"] = calculate_duration(parsed_flow)

    # print(new_flow)

    return new_flow

# update the values based on the new flow found for this IP
def update_IP_values(new_flow, parsed_flow):

    new_flow["in_packets"] = new_flow["in_packets"] + parsed_flow["in_packets"]

    new_flow["in_bytes"] = new_flow["in_bytes"] + parsed_flow["in_bytes"]

    parsed_flow_duration = calculate_duration(parsed_flow)

    new_flow["total_duration"] = new_flow["total_duration"] + parsed_flow_duration

    # print(new_flow)

    return new_flow

# calculate pps and bps based on time duration
def calculate_metrics(flow):

    # print(flow)

    flow["pps"] = flow["in_packets"] / flow["total_duration"]

    flow["bps"] = flow["in_bytes"] / flow["total_duration"]

    return flow

# calculate the duration of a flow, add that duration
# to the total duration of the flow per IP
def calculate_duration(flow):
    from datetime import datetime

    # Define the date format
    date_format = "%Y-%m-%dT%H:%M:%S.%f"

    t_first = datetime.strptime(flow["t_first"], date_format)
    t_last = datetime.strptime(flow["t_last"], date_format)

    duration = abs(t_last - t_first)

    # return the duration in seconds
    return duration.total_seconds()