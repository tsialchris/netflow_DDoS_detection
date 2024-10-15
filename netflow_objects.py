
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

        if flow["in_bytes"] > 0 and flow["in_packets"] > 0 and flow_duration > 0:
            
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

    def calculate_metrics(self):

        # print(flow)

        for destination_IP in self.flows:
            flow = self.flows[destination_IP]

            flow.pps = int(flow.in_packets / (flow.duration / flow.number_of_flows))
            flow.bps = int(flow.in_bytes / (flow.duration / flow.number_of_flows))

            self.set_flow(destination_IP, flow)

            for protocol in flow.protocols:

                # print("successful for")

                protocol_flow = flow.get_protocol(protocol)

                # print(protocol_flow)

                

                # print(protocol_flow.duration)
                # print(protocol_flow.in_bytes)
                # print(protocol_flow.in_packets)

                protocol_flow.pps = int(protocol_flow.in_packets / (protocol_flow.duration / protocol_flow.number_of_flows))
                protocol_flow.bps = int(protocol_flow.in_bytes / (protocol_flow.duration / protocol_flow.number_of_flows))

                # set the metrics
                self.set_protocol(destination_IP, protocol, protocol_flow)

                for port in protocol_flow.ports:
                    # print("successful PORT for")
                    # print(protocol_flow.ports[port].duration)
                    port_flow = protocol_flow.get_port(port)

                    port_flow.pps = int(port_flow.in_packets / (port_flow.duration / port_flow.number_of_flows))
                    port_flow.bps = int(port_flow.in_bytes / (port_flow.duration / port_flow.number_of_flows))

                    self.set_port(destination_IP, protocol, port, port_flow)

        # return flow
    
    def get_top_IP_flows(self, number_of_flows, metric):

        from list_functions import insert_and_overwrite

        self.metric = metric

        top_flows = []

        for flow in self.flows:
            # if the list is empty, populate it
            if len(top_flows) < number_of_flows:
                top_flows.append(flow)
                top_flows.sort(key=top_flows.metric)
            else:
                # find the top values:
                i = 0
                # go through the top_flows, if another value is higher, replace the correct element
                while i < len(top_flows):
                    if flow.metric > top_flows[i].metric:
                        insert_and_overwrite(top_flows, i, flow)
                    i = i + 1



        return top_flows
    
    def get_top_protocol_flows(number_of_flows, metric, protocol):
        top_flows = []

        return top_flows

    def get_top_port_flows(number_of_flows, metric, protocol, port):
        top_flows = []

        return top_flows

    def print_top_flows(top_flows, metric):
        print("----------------TOP FLOWS ", metric, "----------------")




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

        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_packets + flow["in_packets"]
        self.duration = self.duration + flow_duration
        self.number_of_flows = self.number_of_flows + 1

        protocol = str(flow["proto"])

        if not self.protocols:
            new_protocol = netflow_protocol(protocol)
            self.protocols[protocol] = new_protocol
            self.protocols[protocol].add_port(flow, flow_duration)
        else:
            # else if the protocol is already present, add_port
            if protocol in self.protocols:
                self.protocols[protocol].add_port(flow, flow_duration)
            # if the protocol is not present, add it and then add_port
            else:
                new_protocol = netflow_protocol(protocol)
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


    def __init__(self, protocol):
        self.proto = protocol
        self.in_bytes = 0
        self.in_packets = 0
        self.duration = 0
        self.number_of_flows = 0
        self.ports = {}

    # def __init__(self, flow):
    #     from nfdump_functions import calculate_duration
    #     self.proto = flow["proto"]
    #     self.in_bytes = flow["in_bytes"]
    #     self.in_packets = flow["in_packets"]
    #     self.duration = calculate_duration(flow)
    #     self.number_of_flows = 1
    #     self.ports = {}

    def add_port(self, flow, flow_duration):
        
        self.in_bytes = self.in_bytes + flow["in_bytes"]
        self.in_packets = self.in_bytes + flow["in_packets"]
        self.duration = self.duration + flow_duration
        self.number_of_flows = self.number_of_flows + 1

        # some flows do not have a destination port
        try:
            dst_port = str(flow["dst_port"])
        except:
            pass
        try:
            if not self.ports:
                new_port = netflow_port(flow)
                self.ports[dst_port] = new_port
                self.ports[dst_port].update(flow, flow_duration)
            else:
                # if the destination port is already present,
                # update it
                if dst_port in self.ports:
                    self.ports[dst_port].update(flow, flow_duration)
                # if the destination port is not present, create it, add it and update it
                else:
                    new_port = netflow_port(dst_port)
                    self.ports[dst_port].update(flow, flow_duration)
        
        # some flows do not have a destination port
        except:
            # print("ERROR IN PORT PROCESSING")
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
    
    def set_port(self, port_number, port_flow):
        self.ports[port_number] = port_flow



class netflow_port(netflow_protocol):
    def __init__(self, dst_port):
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
