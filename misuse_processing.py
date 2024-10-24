
# SEND NOTIFICATIONS IN THE list_functions.py

# Here, we define the functions used in misuse_objects

# misuse_category_name is used to keep track of the misuse type in case of notifications
# Notifications are to be sent from here when a value exceeds a given threshold

def get_threshold_and_top_IP_flows(netflow_flows, number_of_flows, metric, metric_threshold, top_flag, threshold_flag, misuse_category_name):
        from list_functions import check_and_insert
        from list_functions import threshold_check

        top_flows = []
        threshold_flows = {}

        for index in netflow_flows.flows:
            IP_flow = netflow_flows.flows[index]

            if top_flag:
                # check for max and append if list is empty, overwrite if it is full
                top_flows = check_and_insert(top_flows, IP_flow, number_of_flows, metric)

            if threshold_flag:
                # check if the metric that interests us is over the set threshold
                threshold_flows = threshold_check(threshold_flows, IP_flow, metric, metric_threshold, misuse_category_name)

        sorted_threshold_flows = dict(sorted(threshold_flows.items(), 
                                     key=lambda item: getattr(item[1], metric), 
                                     reverse=True))

        aggregate_flows = [top_flows, sorted_threshold_flows]

        return aggregate_flows


def get_threshold_and_top_protocol_flows(netflow_flows, number_of_flows, metric, metric_threshold, protocol, tcp_flags_var, top_flag, threshold_flag, misuse_category_name):
        from list_functions import check_and_insert
        from list_functions import threshold_check
        
        top_flows = []
        threshold_flows = {}

        for index in netflow_flows.flows:
            
            IP_flow = netflow_flows.flows[index]

            # get the equivalent of netflow_flows.flows[index].protocol
            for protocol_index in IP_flow.protocols:

                # if the protocol provided matches the protocol of the flow
                if protocol == protocol_index:
                    protocol_flow = IP_flow.protocols[protocol]

                    # if we are looking for specific tcp flags (and not for IP_fragments)
                    if not (tcp_flags_var == "none") and not ("IP_fragments" in misuse_category_name):

                        # Do this for every tcp_flag flow
                        if tcp_flags_var in protocol_flow.tcp_flags:

                            flagged_protocol_flow = protocol_flow.tcp_flags[tcp_flags_var]

                            if top_flag:
                                # check for max and append if list is empty, overwrite if it is full
                                top_flows = check_and_insert(top_flows, flagged_protocol_flow, number_of_flows, metric)

                            if threshold_flag:
                                # check if the metric that interests us is over the set threshold
                                threshold_flows = threshold_check(threshold_flows, flagged_protocol_flow, metric, metric_threshold, misuse_category_name)

                    # else, if we are looking for IP fragments
                    elif "IP_fragments" in misuse_category_name:
                        
                        if protocol_flow.IP_fragments:

                            # the IP_fragments dictionary only has a single element, with the identifier always being the dst4_addr
                            fragged_protocol_flow = protocol_flow.IP_fragments[protocol_flow.dst4_addr]

                            if top_flag:
                                # check for max and append if list is empty, overwrite if it is full
                                top_flows = check_and_insert(top_flows, fragged_protocol_flow, number_of_flows, metric)

                            if threshold_flag:
                                # check if the metric that interests us is over the set threshold
                                threshold_flows = threshold_check(threshold_flows, fragged_protocol_flow, metric, metric_threshold, misuse_category_name)
                        
                        else:
                            # print("No fragments found for this flow")
                            pass

                    # else, if we are not looking for any tcp flags or IP fragments:
                    else:
                        if top_flag:
                            # check for max and append if list is empty, overwrite if it is full
                            top_flows = check_and_insert(top_flows, protocol_flow, number_of_flows, metric)

                        if threshold_flag:
                            # check if the metric that interests us is over the set threshold
                            threshold_flows = threshold_check(threshold_flows, protocol_flow, metric, metric_threshold, misuse_category_name)


        sorted_threshold_flows = dict(sorted(threshold_flows.items(), 
                                     key=lambda item: getattr(item[1], metric), 
                                     reverse=True))

        aggregate_flows = [top_flows, sorted_threshold_flows]

        return aggregate_flows


def get_threshold_and_top_port_flows(netflow_flows, number_of_flows, metric, metric_threshold, protocol, port, destination_or_source, top_flag, threshold_flag, misuse_category_name):
        from list_functions import check_and_insert
        from list_functions import threshold_check
        
        top_flows = []
        threshold_flows = {}

        for index in netflow_flows.flows:

            IP_flow = netflow_flows.flows[index]

            # get the equivalent of netflow_flows.flows[index].protocol
            for protocol_index in IP_flow.protocols:

                # if the protocol provided matches the protocol of the flow
                if protocol == protocol_index:

                    protocol_flow = IP_flow.protocols[protocol]

                        
                    # get the correct variable by concating strings and getting the variable from the internal __dict__ maintained at class level
                    port_dictionary = protocol_flow.__dict__[destination_or_source + "_ports"]

                    for port_index in port_dictionary:

                        # if the port provided matches the port of the flow
                        if port == port_index:
                            port_flow = port_dictionary[port]

                            if top_flag:
                                # check for max and append if list is empty, overwrite if it is full
                                top_flows = check_and_insert(top_flows, port_flow, number_of_flows, metric)

                            if threshold_flag:
                                # check if the metric that interests us is over the set threshold
                                threshold_flows = threshold_check(threshold_flows, port_flow, metric, metric_threshold, misuse_category_name)

        
        sorted_threshold_flows = dict(sorted(threshold_flows.items(), 
                                     key=lambda item: getattr(item[1], metric), 
                                     reverse=True))

        aggregate_flows = [top_flows, sorted_threshold_flows]

        return aggregate_flows