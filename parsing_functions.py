def print_top_list(list, metric):
    print("--------TOP FLOWS ", metric, "--------")
    for flow in list:
        print(flow["dst4_addr"], " : ", int(flow[metric]))

    print("------------------------------")

def print_over_threshold_list(list, metric):
    print("--------FLOWS OVER THRESHOLD ", metric, "--------")
    for flow in list:
        print(flow["dst4_addr"], " : ", int(flow[metric]))

    print("------------------------------")


# def flows_over_threshold_check(flows_over_threshold, flow, protocol, port):

#     bbs_threshold = 10000

#     pps_threshold = 100
    
#     if (flow["proto"] == protocol or protocol == "protocol_irrelevant") and (flow["dst_port"] == port or port == "port_irrelevant"):

#         if flow["bps"] > bbs_threshold:
#             flows_over_threshold.append(flow)
        
#         elif flow["pps"] > pps_threshold:
#             flows_over_threshold.append(flow)

#     return flows_over_threshold