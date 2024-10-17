
# overall container for all flows
class netflows():

    def __init__(self):
        self.flows = {}

    # add a flow to the destination_IP key
    # WARNING: This takes an unprocessed .json flow as input
    def add_flow(self, flow):

        # disregard empty flows:
        from nfdump_functions import calculate_duration
        flow_duration = calculate_duration(flow)

        if (flow["in_bytes"] > 0 or flow["in_packets"] > 0) and (not ("dst6_addr" in flow)):

            # ASSUMPTION: IGNORE any ipv6 packets

            # print(flow)
            # flow_duration = calculate_duration(flow)
            destination_IP = flow["dst4_addr"]

            # if the flows are empty, simply append
            if not self.flows:
                new_flow = netflow_flow(destination_IP)
                self.flows[destination_IP] = new_flow
                self.flows[destination_IP].add_protocol(flow, flow_duration)
            # else, if the flows are not empty
            else:
                # check if this destination_IP already exists
                # if it does, update it
                if destination_IP in self.flows:
                    self.flows[destination_IP].add_protocol(flow, flow_duration)
                # if the destination_IP is not present, add it and then add_protocol
                else:
                    new_flow = netflow_flow(destination_IP)
                    self.flows[destination_IP] = new_flow
                    self.flows[destination_IP].add_protocol(flow, flow_duration)

    # def has_flow(self, destination_IP):
    #     if destination_IP in self.flows:
    #         return True
    #     return False
    
    def get_flow(self, destination_IP):
        return self.flows[destination_IP]
    
    def set_flow(self, destination_IP, flow):
        self.flows[destination_IP] = flow

    def set_protocol(self, destination_IP, protocol, flow):
        self.flows[destination_IP].set_protocol(protocol, flow)

    def set_port(self, destination_IP, protocol, port, flow):
        self.flows[destination_IP].protocols[protocol].set_port(port, flow)

    def set_tcp_flag(self, destination_IP, protocol, tcp_flag_var, flow):
        self.flows[destination_IP].protocols[protocol].set_tcp_flag(tcp_flag_var, flow)

    def calculate_metrics(self):

        # print(flow)

        file_duration = 300

        for destination_IP in self.flows:
            flow = self.flows[destination_IP]

            # ASSUMPTION: if duration == 0, duration = 1
            # this makes it easy to catch
            # a lot of flows have a duration of 0
            # do normal flows have a duration of 0?
            if flow.duration == 0:
                flow.duration = 1

            # METHOD 1
            # flow.pps = int(flow.in_packets / (flow.duration / flow.number_of_flows))
            # flow.bps = int(flow.in_bytes / (flow.duration / flow.number_of_flows))

            # METHOD 2
            flow.pps = int(flow.in_packets / file_duration)
            flow.bps = int(flow.in_bytes / file_duration)

            self.set_flow(destination_IP, flow)

            for protocol in flow.protocols:

                protocol_flow = flow.get_protocol(protocol)

                # ASSUMPTION: if duration == 0, duration = 1
                # this makes it easy to catch
                # a lot of flows have a duration of 0
                # do normal flows have a duration of 0?
                if protocol_flow.duration == 0:
                    protocol_flow.duration = 1

                # METHOD 1
                # protocol_flow.pps = int(protocol_flow.in_packets / (protocol_flow.duration / protocol_flow.number_of_flows))
                # protocol_flow.bps = int(protocol_flow.in_bytes / (protocol_flow.duration / protocol_flow.number_of_flows))

                # METHOD 2
                protocol_flow.pps = int(protocol_flow.in_packets / file_duration)
                protocol_flow.bps = int(protocol_flow.in_bytes / file_duration)

                # set the metrics
                self.set_protocol(destination_IP, protocol, protocol_flow)

                for tcp_flag_var in protocol_flow.tcp_flags:
                    tcp_flag_flow = protocol_flow.get_tcp_flag(tcp_flag_var)

                    if tcp_flag_flow.duration == 0:
                        tcp_flag_flow.duration = 1

                    # METHOD 1
                    # tcp_flag_flow.pps = int(tcp_flag_flow.in_packets / (tcp_flag_flow.duration / tcp_flag_flow.number_of_flows))
                    # tcp_flag_flow.bps = int(tcp_flag_flow.in_bytes / (tcp_flag_flow.duration / tcp_flag_flow.number_of_flows))

                    # METHOD 2
                    tcp_flag_flow.pps = int(tcp_flag_flow.in_packets / file_duration)
                    tcp_flag_flow.bps = int(tcp_flag_flow.in_bytes / file_duration)

                    self.set_tcp_flag(destination_IP, protocol, tcp_flag_var, tcp_flag_flow)


                for port in protocol_flow.ports:
                    port_flow = protocol_flow.get_port(port)

                    # ASSUMPTION: if duration == 0, duration = 1
                    # this makes it easy to catch
                    # a lot of flows have a duration of 0
                    # do normal flows have a duration of 0?
                    if port_flow.duration == 0:
                        port_flow.duration = 1

                    # METHOD 1
                    # port_flow.pps = int(port_flow.in_packets / (port_flow.duration / port_flow.number_of_flows))
                    # port_flow.bps = int(port_flow.in_bytes / (port_flow.duration / port_flow.number_of_flows))

                    # METHOD 2
                    port_flow.pps = int(port_flow.in_packets / file_duration)
                    port_flow.bps = int(port_flow.in_bytes / file_duration)


                    self.set_port(destination_IP, protocol, port, port_flow)

        # return flow
    
    def get_threshold_and_top_IP_flows(self, number_of_flows, metric, metric_threshold, top_flag, threshold_flag):
        from list_functions import check_and_insert
        from list_functions import threshold_check

        top_flows = []
        threshold_flows = {}

        for index in self.flows:
            IP_flow = self.flows[index]

            if top_flag:
                # check for max and append if list is empty, overwrite if it is full
                top_flows = check_and_insert(top_flows, IP_flow, number_of_flows, metric)

            if threshold_flag:
                # check if the metric that interests us is over the set threshold
                threshold_flows = threshold_check(threshold_flows, IP_flow, metric, metric_threshold)

        # print(self.print_top_flows(top_flows, metric))

        sorted_threshold_flows = dict(sorted(threshold_flows.items(), 
                                     key=lambda item: getattr(item[1], metric), 
                                     reverse=True))

        aggregate_flows = [top_flows, sorted_threshold_flows]

        return aggregate_flows
    
    def get_threshold_and_top_protocol_flows(self, number_of_flows, metric, metric_threshold, protocol, tcp_flags_var, top_flag, threshold_flag):
        from list_functions import check_and_insert
        from list_functions import threshold_check
        import re
        
        top_flows = []
        threshold_flows = {}

        for index in self.flows:
            
            IP_flow = self.flows[index]

            # get the equivalent of self.flows[index].protocol
            for protocol_index in IP_flow.protocols:

                # if the protocol provided matches the protocol of the flow
                if protocol == protocol_index:
                    protocol_flow = IP_flow.protocols[protocol]


                    if tcp_flags_var in protocol_flow.tcp_flags:
                        # print(protocol_flow.tcp_flags)
                        # print(tcp_flags_var)

                        flagged_protocol_flow = protocol_flow.tcp_flags[tcp_flags_var]

                        # print("AFTER THE FLAGGING")

                        if top_flag:
                            # check for max and append if list is empty, overwrite if it is full
                            top_flows = check_and_insert(top_flows, flagged_protocol_flow, number_of_flows, metric)

                        if threshold_flag:
                            # check if the metric that interests us is over the set threshold
                            threshold_flows = threshold_check(threshold_flows, flagged_protocol_flow, metric, metric_threshold)

                    # # print(protocol_flow.tcp_flags)
                    # # if tcp_flags is unset, ignore them
                    # if tcp_flags == "'........'":
                    # # print(protocol_flow.tcp_flags)
                    # # if re.match("\.{9}", protocol_flow.tcp_flags,):
                    #     if top_flag:
                    #         # check for max and append if list is empty, overwrite if it is full
                    #         top_flows = check_and_insert(top_flows, protocol_flow, number_of_flows, metric)

                    #     if threshold_flag:
                    #         # check if the metric that interests us is over the set threshold
                    #         threshold_flows = threshold_check(threshold_flows, protocol_flow, metric, metric_threshold)
                    
                    # # else, if we are looking for a specific pattern of tcp_flags:
                    # # do the same only when it is matched
                    # else:
                    #     # if protocol_flow.tcp_flags == "......S.":
                    #     # if re.match("\.\.\.\.\.\.S\.", protocol_flow.tcp_flags):
                    #     #     print("SYN FLOW")
                    #     # print(tcp_flags, "==", protocol_flow.tcp_flags)
                    #     if tcp_flags == protocol_flow.tcp_flags:
                    #     # if re.match(tcp_flags, protocol_flow.tcp_flags):
                    #         if top_flag:
                    #             # check for max and append if list is empty, overwrite if it is full
                    #             top_flows = check_and_insert(top_flows, protocol_flow, number_of_flows, metric)

                    #         if threshold_flag:
                    #             # check if the metric that interests us is over the set threshold
                    #             threshold_flows = threshold_check(threshold_flows, protocol_flow, metric, metric_threshold)
        
        # print(self.print_top_flows(top_flows, metric))

        sorted_threshold_flows = dict(sorted(threshold_flows.items(), 
                                     key=lambda item: getattr(item[1], metric), 
                                     reverse=True))

        aggregate_flows = [top_flows, sorted_threshold_flows]

        return aggregate_flows

    def get_threshold_and_top_port_flows(self, number_of_flows, metric, metric_threshold, protocol, port, top_flag, threshold_flag):
        from list_functions import check_and_insert
        from list_functions import threshold_check
        
        top_flows = []
        threshold_flows = {}

        for index in self.flows:

            IP_flow = self.flows[index]

            # get the equivalent of self.flows[index].protocol
            for protocol_index in IP_flow.protocols:

                # if the protocol provided matches the protocol of the flow
                if protocol == protocol_index:

                    protocol_flow = IP_flow.protocols[protocol]

                    for port_index in protocol_flow.ports:

                        # if the port provided matches the port of the flow
                        if port == port_index:
                            port_flow = protocol_flow.ports[port]

                            if top_flag:
                                # check for max and append if list is empty, overwrite if it is full
                                top_flows = check_and_insert(top_flows, port_flow, number_of_flows, metric)

                            if threshold_flag:
                                # check if the metric that interests us is over the set threshold
                                threshold_flows = threshold_check(threshold_flows, port_flow, metric, metric_threshold)
        
        # print(self.print_top_flows(top_flows, metric))

        sorted_threshold_flows = dict(sorted(threshold_flows.items(), 
                                     key=lambda item: getattr(item[1], metric), 
                                     reverse=True))

        aggregate_flows = [top_flows, sorted_threshold_flows]

        return aggregate_flows

    def print_top_flows(self, top_flows, metric):
        print("------- TOP FLOWS", metric, "-------")

        for flow in top_flows:
            print (flow.dst4_addr, ":", getattr(flow, metric))

        print("-----------------------------")

    def print_threshold_flows(self, threshold_flows, metric):
        print("------ FLOWS OVER THRESHOLD", metric, "------")

        for index in threshold_flows:
            flow = threshold_flows[index]
            print (flow.dst4_addr, ":", getattr(flow, metric))

        # print(threshold_flows)
        
        # for flow in threshold_flows:
        #     print(flow)
        #     print (flow.dst4_addr, ":", getattr(flow, metric))

        print("--------------------------------------")


class netflow_flow:
    
    def __init__(self, destination_IP):
        self.dst4_addr = destination_IP
        self.in_bytes = 0
        self.in_packets = 0
        self.duration = 0
        self.number_of_flows = 0
        self.protocols = {}

    # def __init__(self, flow, flow_duration):
    #     self.dst4_addr = flow["dst4_addr"]
    #     self.in_bytes = flow["in_bytes"]
    #     self.in_packets = flow["in_packets"]
    #     self.duration = flow_duration
    #     self.number_of_flows = 0
    #     self.protocols = {}

    def add_protocol(self, flow, flow_duration):
        import re

        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.duration = self.duration + flow_duration
        self.number_of_flows = self.number_of_flows + 1

        protocol = str(flow["proto"])

        tcp_flags = repr(flow["tcp_flags"])
        # print(tcp_flags)

        if not self.protocols:
            # print(tcp_flags)
            new_protocol = netflow_protocol(protocol, self.dst4_addr, tcp_flags)
            self.protocols[protocol] = new_protocol
            self.protocols[protocol].add_port(flow, flow_duration)
        else:
            # else if the protocol is already present, add_port
            # print(tcp_flags)
            guard = True
            if protocol in self.protocols:
                # print(tcp_flags)
                # need to check for flags as well before adding!
                # TO DO
                # NEW FLAGS ARE CONSIDERED NEW PORTS... will have to make do with that...
                for search_protocol in self.protocols:
                    # print(self.protocols[search_protocol].tcp_flags, "==", repr(tcp_flags))
                    # print(repr(self.protocols[search_protocol].tcp_flags), "==", repr(tcp_flags))
                    # re.match("\.{9}", protocol_flow.tcp_flags,)

                    # ============================= IRRELEVANT RANT AND COMMENTS =============================
                    # THIS CHECK DOES NOT WORK...
                    # if re.match(tcp_flags, self.protocols[search_protocol].tcp_flags):
                    # ...AP... == ........
                    # This check does not work either...
                    # if(self.protocols[search_protocol].tcp_flags == tcp_flags):
                    # ...APRS. == ...AP...
                    # if (self.protocols[search_protocol].tcp_flags) == (str((tcp_flags))):
                    # ONLY THIS WORKED FFS... :(
                    # if self.protocols[search_protocol].tcp_flags == repr(tcp_flags):
                    # ============================= IRRELEVANT RANT AND COMMENTS =============================

                    for tcp_flag_var in self.protocols[search_protocol].tcp_flags:
                        if tcp_flag_var == repr(tcp_flags):
                            # print("...APRS." == "...AP...")
                            # print(repr(self.protocols[search_protocol].tcp_flags), "==", repr(tcp_flags))
                            # print(self.protocols[search_protocol].tcp_flags, "==", tcp_flags)
                            self.protocols[search_protocol].add_port(flow, flow_duration)
                            guard = False
                            break

                    if not guard:
                        break
                
                # if the protocol exists, but the specific tcp_flags do not:
                # need to find a mechanism to add a new tcp_flag
                if guard:
                    self.protocols[protocol].add_port(flow, flow_duration)

            # if the protocol is not present, add it and then add_port
            # DO NOT FORGET! ALSO ADD THE TCP FLAG!
            else:
                # print(self.dst4_addr, ":", tcp_flags)
                new_protocol = netflow_protocol(protocol, self.dst4_addr, tcp_flags)
                self.protocols[protocol] = new_protocol
                self.protocols[protocol].add_port(flow, flow_duration)


    # def update(self, flow, flow_duration):
    #     self.in_bytes = self.in_bytes + flow["in_bytes"]
    #     self.in_packets = self.in_packets + flow["in_packets"]
    #     self.number_of_flows = self.number_of_flows + 1
    #     self.duration = self.duration + flow_duration

    # def has_protocol(self, identifier):
    #     if identifier in self.protocols:
    #         return True
    #     return False
    
    def get_protocol(self, identifier):
        return self.protocols[identifier]
    
    def set_protocol(self, identifier, protocol_flow):
        self.protocols[identifier] = protocol_flow


# Note: __slots__ could be useful

class netflow_protocol(netflow_flow):


    def __init__(self, protocol, dst4_addr, tcp_flags):
        self.dst4_addr = dst4_addr
        self.proto = protocol
        self.in_bytes = 0
        self.in_packets = 0
        self.duration = 0
        self.number_of_flows = 0
        self.ports = {}
        self.tcp_flags = {}
        # self.tcp_flags = repr(tcp_flags)

    # def __init__(self, flow):
    #     from nfdump_functions import calculate_duration
    #     self.proto = flow["proto"]
    #     self.in_bytes = flow["in_bytes"]
    #     self.in_packets = flow["in_packets"]
    #     self.duration = calculate_duration(flow)
    #     self.number_of_flows = 1
    #     self.ports = {}

    def add_tcp_flag(self, flow, flow_duration):
        tcp_flag_string = repr(flow["tcp_flags"])

        if not self.tcp_flags:
            new_tcp_flag = tcp_flag(tcp_flag_string, self.dst4_addr)
            self.tcp_flags[tcp_flag_string] = new_tcp_flag
            self.tcp_flags[tcp_flag_string].update(flow, flow_duration)
        else:
            # if the destination port is already present,
            # update it
            if tcp_flag_string in self.tcp_flags:
                self.tcp_flags[tcp_flag_string].update(flow, flow_duration)
            # if the tcp flag is not present, create it, add it and update it
            else:
                new_tcp_flag = tcp_flag(tcp_flag_string, self.dst4_addr)
                self.tcp_flags[tcp_flag_string] = new_tcp_flag
                self.tcp_flags[tcp_flag_string].update(flow, flow_duration)
    
    def add_port(self, flow, flow_duration):
        
        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.duration = self.duration + flow_duration
        self.number_of_flows = self.number_of_flows + 1

        self.add_tcp_flag(flow, flow_duration)

        # some flows do not have a destination port
        try:
            dst_port = str(flow["dst_port"])
        except:
            pass
        try:
            if not self.ports:
                new_port = netflow_port(dst_port, self.dst4_addr)
                self.ports[dst_port] = new_port
                self.ports[dst_port].update(flow, flow_duration)
            else:
                # if the destination port is already present,
                # update it
                if dst_port in self.ports:
                    self.ports[dst_port].update(flow, flow_duration)
                # if the destination port is not present, create it, add it and update it
                else:
                    new_port = netflow_port(dst_port, self.dst4_addr)
                    self.ports[dst_port] = new_port
                    self.ports[dst_port].update(flow, flow_duration)
        
        # some flows do not have a destination port
        except:
            print("ERROR IN PORT PROCESSING")
            pass
        # print(self.ports)


    # def update(self, flow, flow_duration):
    #     self.in_bytes = self.in_bytes + flow["in_bytes"]
    #     self.in_packets = self.in_packets + flow["in_packets"]
    #     self.number_of_flows = self.number_of_flows + 1
    #     self.duration = self.duration + flow_duration

    # def has_port(self, port_number):
    #     if port_number in self.ports:
    #         return True
    #     return False
    
    def get_port(self, port_number):
        return self.ports[port_number]
    
    def get_tcp_flag(self, tcp_flag_var):
        return self.tcp_flags[tcp_flag_var]
    
    def set_port(self, port_number, port_flow):
        self.ports[port_number] = port_flow

    def set_tcp_flag(self, tcp_flag_var, tcp_flag_flow):
        self.ports[tcp_flag_var] = tcp_flag_flow



class netflow_port(netflow_protocol):
    def __init__(self, dst_port, dst4_addr):
        self.dst4_addr = dst4_addr
        self.dst_port = dst_port
        self.in_bytes = 0
        self.in_packets = 0
        self.number_of_flows = 0
        self.duration = 0

    def update(self, flow, flow_duration):
        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.number_of_flows = self.number_of_flows + 1
        self.duration = self.duration + flow_duration

class tcp_flag(netflow_protocol):
    def __init__(self, flag, dst4_addr):
        self.dst4_addr = dst4_addr

        self.flag = flag
        
        self.in_bytes = 0
        self.in_packets = 0
        self.number_of_flows = 0
        self.duration = 0
    
    def update(self, flow, flow_duration):
        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.number_of_flows = self.number_of_flows + 1
        self.duration = self.duration + flow_duration