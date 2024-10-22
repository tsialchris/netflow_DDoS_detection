
# SEND NOTIFICATIONS IN THE list_functions.py


# overall container for all flows
class netflows:

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

    def get_flow(self, destination_IP):
        return self.flows[destination_IP]
    
    def set_flow(self, destination_IP, flow):
        self.flows[destination_IP] = flow

    def set_protocol(self, destination_IP, protocol, flow):
        self.flows[destination_IP].set_protocol(protocol, flow)

    def set_dst_port(self, destination_IP, protocol, port, flow):
        self.flows[destination_IP].protocols[protocol].set_dst_port(port, flow)

    def set_src_port(self,destination_IP, protocol, port, flow):
        self.flows[destination_IP].protocols[protocol].set_src_port(port, flow)

    def set_tcp_flag(self, destination_IP, protocol, tcp_flag_var, flow):
        self.flows[destination_IP].protocols[protocol].set_tcp_flag(tcp_flag_var, flow)

    def calculate_metrics(self):

        # print(flow)

        # CISCO default polling interval is 10 seconds
        # file_duration = 10

        # Collector limit is 2 minutes
        file_duration = 120

        for destination_IP in self.flows:
            flow = self.flows[destination_IP]

            # ASSUMPTION: if duration == 0, duration = 1
            # this makes it easy to catch
            # a lot of flows have a duration of 0
            # do normal flows have a duration of 0?
            if flow.duration == 0:
                flow.duration = 1

            # METHOD 1
            flow.pps = int(flow.in_packets / (flow.duration / flow.number_of_flows))
            flow.bps = int(flow.in_bytes / (flow.duration / flow.number_of_flows))

            # METHOD 2
            # flow.pps = int(flow.in_packets / file_duration)
            # flow.bps = int(flow.in_bytes / file_duration)

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
                protocol_flow.pps = int(protocol_flow.in_packets / (protocol_flow.duration / protocol_flow.number_of_flows))
                protocol_flow.bps = int(protocol_flow.in_bytes / (protocol_flow.duration / protocol_flow.number_of_flows))

                # METHOD 2
                # protocol_flow.pps = int(protocol_flow.in_packets / file_duration)
                # protocol_flow.bps = int(protocol_flow.in_bytes / file_duration)

                # set the metrics
                self.set_protocol(destination_IP, protocol, protocol_flow)

                for tcp_flag_var in protocol_flow.tcp_flags:
                    tcp_flag_flow = protocol_flow.get_tcp_flag(tcp_flag_var)

                    if tcp_flag_flow.duration == 0:
                        tcp_flag_flow.duration = 1

                    # METHOD 1
                    tcp_flag_flow.pps = int(tcp_flag_flow.in_packets / (tcp_flag_flow.duration / tcp_flag_flow.number_of_flows))
                    tcp_flag_flow.bps = int(tcp_flag_flow.in_bytes / (tcp_flag_flow.duration / tcp_flag_flow.number_of_flows))

                    # METHOD 2
                    # tcp_flag_flow.pps = int(tcp_flag_flow.in_packets / file_duration)
                    # tcp_flag_flow.bps = int(tcp_flag_flow.in_bytes / file_duration)

                    self.set_tcp_flag(destination_IP, protocol, tcp_flag_var, tcp_flag_flow)


                for port in protocol_flow.dst_ports:
                    port_flow = protocol_flow.get_dst_port(port)

                    # ASSUMPTION: if duration == 0, duration = 1
                    # this makes it easy to catch
                    # a lot of flows have a duration of 0
                    # do normal flows have a duration of 0?
                    if port_flow.duration == 0:
                        port_flow.duration = 1

                    # METHOD 1
                    port_flow.pps = int(port_flow.in_packets / (port_flow.duration / port_flow.number_of_flows))
                    port_flow.bps = int(port_flow.in_bytes / (port_flow.duration / port_flow.number_of_flows))

                    # METHOD 2
                    # port_flow.pps = int(port_flow.in_packets / file_duration)
                    # port_flow.bps = int(port_flow.in_bytes / file_duration)


                    self.set_dst_port(destination_IP, protocol, port, port_flow)


                for port in protocol_flow.src_ports:
                    port_flow = protocol_flow.get_src_port(port)

                    # ASSUMPTION: if duration == 0, duration = 1
                    # this makes it easy to catch
                    # a lot of flows have a duration of 0
                    # do normal flows have a duration of 0?
                    if port_flow.duration == 0:
                        port_flow.duration = 1

                    # METHOD 1
                    port_flow.pps = int(port_flow.in_packets / (port_flow.duration / port_flow.number_of_flows))
                    port_flow.bps = int(port_flow.in_bytes / (port_flow.duration / port_flow.number_of_flows))

                    # METHOD 2
                    # port_flow.pps = int(port_flow.in_packets / file_duration)
                    # port_flow.bps = int(port_flow.in_bytes / file_duration)


                    self.set_src_port(destination_IP, protocol, port, port_flow)
                    

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

    def add_protocol(self, flow, flow_duration):
        import re

        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.duration = self.duration + flow_duration
        self.number_of_flows = self.number_of_flows + 1

        protocol = str(flow["proto"])

        if "tcp_flags" in flow:
            tcp_flags = repr(flow["tcp_flags"])
        else:
            tcp_flags = repr("........")


        # if the protocols table is empty, add the first element
        if not self.protocols:
            new_protocol = netflow_protocol(self, protocol, self.dst4_addr, tcp_flags)
            self.protocols[protocol] = new_protocol
            self.protocols[protocol].add_port_and_flag(flow, flow_duration)
        else:
            # else if the protocol is already present, add_port_and_flag
            guard = True
            if protocol in self.protocols:

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
                    # if tcp_flag_var == repr(tcp_flags):
                    # ============================= IRRELEVANT RANT AND COMMENTS =============================

                    for tcp_flag_var in self.protocols[search_protocol].tcp_flags:
                        if tcp_flag_var == repr(tcp_flags):
                            # print("...APRS." == "...AP...")
                            # print(repr(self.protocols[search_protocol].tcp_flags), "==", repr(tcp_flags))
                            # print(self.protocols[search_protocol].tcp_flags, "==", tcp_flags)
                            self.protocols[search_protocol].add_port_and_flag(flow, flow_duration)
                            guard = False
                            break

                    if not guard:
                        break
                
                # if the protocol exists, but the specific tcp_flags do not:
                # simply add port (this adds a new tcp_flag as well)
                if guard:
                    self.protocols[protocol].add_port_and_flag(flow, flow_duration)

            # if the protocol is not present, add it and then add_port_and_flag
            # DO NOT FORGET! ALSO ADD THE TCP FLAG! (This is done automatically at add_port_and_flag)
            else:
                # print(self.dst4_addr, ":", tcp_flags)
                new_protocol = netflow_protocol(self, protocol, self.dst4_addr, tcp_flags)
                self.protocols[protocol] = new_protocol
                self.protocols[protocol].add_port_and_flag(flow, flow_duration)
    
    def get_protocol(self, identifier):
        return self.protocols[identifier]
    
    def set_protocol(self, identifier, protocol_flow):
        self.protocols[identifier] = protocol_flow


# Note: __slots__ could be useful

# goes in netflow_flow
class netflow_protocol(netflow_flow):


    def __init__(self, parent_flow, protocol, dst4_addr, tcp_flags):
        self.parent_flow = parent_flow
        self.dst4_addr = dst4_addr
        self.proto = protocol
        self.in_bytes = 0
        self.in_packets = 0
        self.duration = 0
        self.number_of_flows = 0
        self.dst_ports = {}
        # self.destinaton_ports = {}
        self.src_ports = {}
        # self.source_ports = {}
        self.tcp_flags = {}

        # IP_fragments have dst_port == "0" and src_port == "0"
        # this will be a dictionary with only ONE element present
        # the identifier is the dst4_addr, as a result only one element will be present and the key is the self.dst4_addr
        self.IP_fragments = {}
        
    
    def add_port_and_flag(self, flow, flow_duration):
        
        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.duration = self.duration + flow_duration
        self.number_of_flows = self.number_of_flows + 1

        self.add_tcp_flag(flow, flow_duration)

        if "dst_port" in flow:
            self.dst_ports = self.add_source_or_destination_port(flow, "dst", flow_duration)

        # do the same as in dst_ports
        if "src_port" in flow:
            self.src_ports = self.add_source_or_destination_port(flow, "src", flow_duration)

        # if both dst_port and src_port are present (i.e., most cases)
        # if both of them == "0" and tcp_flags == repr("........") add to IP_fragments

        # print(repr(flow["tcp_flags"]) , "==", repr("........"))
        # print(repr(flow["tcp_flags"]) == repr("........"))
        
        if ("dst_port" in flow) and ("src_port" in flow):
            if str(flow["dst_port"]) == "0" and str(flow["src_port"]) == "0"and repr(flow["tcp_flags"]) == repr("........"):
                # print("in IP fragment misuse")
                self.IP_fragments = self.add_to_category(self.IP_fragments, "IP_fragment", self.dst4_addr, flow, flow_duration)


    def add_to_category(self, dictionary, object_name, identifier, flow, flow_duration):
        import sys
        import inspect

        if not dictionary:
            # print(tuple(sys.modules))
            # print(inspect.getmembers(sys.modules[object_name]))

            # create the object based on the classes that are available
            # match the object_name variable with the available classes and then create the object based on that
            for name, obj in inspect.getmembers(sys.modules[__name__]):
                # if inspect.isclass(obj):
                # print(name, "==", object_name)
                if name == object_name:
                    # print(obj)
                    new_object = obj(self, identifier, self.dst4_addr)
                    
            dictionary[identifier] = new_object
            dictionary[identifier].update(flow, flow_duration)
        else:
            # if the destination port is already present,
            # update it
            if identifier in dictionary:
                dictionary[identifier].update(flow, flow_duration)
            # if the tcp flag is not present, create it, add it and update it
            else:
                # create the object based on the classes that are available
                # match the object_name variable with the available classes and then create the object based on that
                for name, obj in inspect.getmembers(sys.modules[__name__]):
                    # if inspect.isclass(obj):
                    # print(name, "==", object_name)
                    if name == object_name:
                        # print(obj)
                        new_object = obj(self, identifier, self.dst4_addr)
                dictionary[identifier] = new_object
                dictionary[identifier].update(flow, flow_duration)

        return dictionary

    def add_tcp_flag(self, flow, flow_duration):

        if "tcp_flags" in flow:
            tcp_flag_string = repr(flow["tcp_flags"])
        else:
            tcp_flag_string = repr("........")

        self.tcp_flags = self.add_to_category(self.tcp_flags, "tcp_flag", tcp_flag_string, flow, flow_duration)


    def add_source_or_destination_port(self, flow, port_var, flow_duration):

        port_key = port_var + "_port"
        
        port = str(flow[port_key])

        # create the correct variable
        # "destination" + "_ports"
        # "source" + "_ports"
        port_dictionary = self.__dict__[port_var + "_ports"]
        
        port_dictionary = self.add_to_category(port_dictionary, "netflow_port", port, flow, flow_duration)

        return port_dictionary


    def get_dst_port(self, port_number):
        return self.dst_ports[port_number]
    
    def get_src_port(self, port_number):
        return self.src_ports[port_number]
    
    def get_tcp_flag(self, tcp_flag_var):
        return self.tcp_flags[tcp_flag_var]
    
    def set_dst_port(self, port_number, port_flow):
        self.dst_ports[port_number] = port_flow

    def set_src_port(self, port_number, port_flow):
        self.src_ports[port_number] = port_flow

    def set_tcp_flag(self, tcp_flag_var, tcp_flag_flow):
        self.dst_ports[tcp_flag_var] = tcp_flag_flow


# goes in netflow_protocol
class netflow_port(netflow_protocol):
    def __init__(self, parent_protocol, dst_port, dst4_addr):
        self.parent_protocol = parent_protocol
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

# goes in netflow_protocol
class tcp_flag:
    def __init__(self, parent_protocol, flag, dst4_addr):

        self.parent_protocol = parent_protocol

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

# goes in netflow_protocol
class IP_fragment:
    def __init__(self, parent_protocol, identifier, dst4_addr):

        self.parent_protocol = parent_protocol

        self.dst4_addr = dst4_addr

        # identifier is added as input for compatibility reasons (add_to_category_function)
        # the identifier is always == dst4_addr
        # since this is the IP_fragment identifier
        self.identifier = dst4_addr
        
        self.in_bytes = 0
        self.in_packets = 0
        self.number_of_flows = 0
        self.duration = 0
    
    def update(self, flow, flow_duration):
        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.number_of_flows = self.number_of_flows + 1
        self.duration = self.duration + flow_duration
