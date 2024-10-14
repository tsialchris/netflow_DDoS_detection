
class netflow_flow:
    dst4_addr = "no_address"
    in_bytes = 0
    in_packets = 0
    duration = 0
    protocols = {}    
    def __init__(self):
        self.dst4_addr = "no_address"
        self.in_bytes = 0
        self.in_packets = 0
        self.duration = 0
        self.protocols = {}

    def add_protocol(self, identifier, in_bytes, in_packets, duration):
        if not self.protocols:
            





class netflow_protocol:
    def __init__(self):
        in_bytes = 0
        in_packets = 0
        duration = 0
        ports = {}


class netflow_port_number:
    def __init__(self):
        in_bytes = 0
        in_packets = 0
        duration = 0
