
# Here we define the misuse cases

# SEND NOTIFICATIONS IN THE list_functions.py


from misuse_processing import get_threshold_and_top_IP_flows
from misuse_processing import get_threshold_and_top_protocol_flows
from misuse_processing import get_threshold_and_top_port_flows


def total_traffic(netflow_flows, number_of_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_IP_flows(netflow_flows, number_of_flows, metric, metric_threshold, True, True, "total_traffic")

    return aggregate_flows


def total_UDP_traffic(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "none", True, True, "total_UDP_traffic")

    return aggregate_flows


def total_TCP_no_flags(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr("........"), True, True, "total_TCP_no_flags")

    return aggregate_flows


def TCP_only_RST(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr(".....R.."), True, True, "TCP_only_RST")

    return aggregate_flows


def TCP_only_SYN(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr("......S."), True, True, "TCP_only_SYN")

    return aggregate_flows


def TCP_only_FIN(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr(".......F"), True, True, "TCP_only_FIN")

    return aggregate_flows

def total_DNS(netflow_flows, amount_top_flows, metric, metric_threshold):

    # total traffic with DNS destination port
    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "53", "dst", True, True, "total_DNS - destination port")

    return aggregate_flows

def total_X_port_destination(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port):

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port, "dst", True, True, "total_X_port_destination")

    return aggregate_flows

def total_X_port_source(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port):

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port, "src", True, True, "total_X_port_source")

    return aggregate_flows


def total_ICMP(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "1"
    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "1", "none", True, True, "total_ICMP")

    return aggregate_flows

def chargen_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # NEEDS TESTING! #

    # protocol == "17" (UDP)
    # source_port == "19"
    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "19", "src", True, True, "chargen_amplification")
    
    return aggregate_flows

def CLDAP_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # NEEDS TESTING! #

    # protocol == "17" (UDP)
    # source_port == "389"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "389", "src", True, True, "CLDAP_amplification")
    
    return aggregate_flows

def DNS_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # NEEDS TESTING! #

    # protocol == "17" (UDP)
    # source_port == "53"
    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "53", "src", True, True, "DNS_amplification")
    
    return aggregate_flows

def TCP_IP_fragments(netflow_flows, amount_top_flows, metric, metric_threshold):

    # NEEDS TESTING! #

    # Non-initial packet fragments. Source and destination port are zero and no TCP flags are set.
    # protocol == "6" (TCP)
    # src_port == "0"
    # dst_port == "0"
    # tcp_flags == repr("........")

    # aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", "0", "src", True, True, "TCP_IP_fragments")

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", "none", True, True, "TCP_IP_fragments")
    
    return aggregate_flows

def UDP_IP_fragments(netflow_flows, amount_top_flows, metric, metric_threshold):

    # NEEDS TESTING! #

    # protocol == "17" (UDP)
    # src_port == "0"
    # dst_port == "0"
    # tcp_flags == repr("........")

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "none", True, True, "UDP_IP_fragments")

    return aggregate_flows

def IPv4_protocol_0(netflow_flows, amount_top_flows, metric, metric_threshold):
    
    # protocol == "0" (invalid)

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "0", "none", True, True, "IPv4_protocol_0")

    return aggregate_flows

def mDNS_reflection_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # mDNS == multicast DNS

    # protocol == "17" (UDP)
    # src_port == "5353"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "5353", "src", True, True, "mDNS_reflection_amplification")

    return aggregate_flows

def memcached_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "11211"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "11211", "src", True, True, "memcached_amplification")

    return aggregate_flows

def MS_SQL_RS_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "1434"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "1434", "src", True, True, "MS_SQL_RS_amplification")

    return aggregate_flows

def netbios_reflection_amplification_1(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "137"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "137", "src", True, True, "netbios_reflection_amplification_1")

    return aggregate_flows

def netbios_reflection_amplification_2(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "138"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "138", "src", True, True, "netbios_reflection_amplification_2")

    return aggregate_flows

def RIPv1_reflection_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "520"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "520", "src", True, True, "RIPv1_reflection_amplification")

    return aggregate_flows

def rpcbind_reflection_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "111"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "111", "src", True, True, "rpcbind_reflection_amplification")

    return aggregate_flows

def SNMP_amplification_1(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "161"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "161", "src", True, True, "SNMP_amplification_1")

    return aggregate_flows

def SNMP_amplification_2(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "162"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "162", "src", True, True, "SNMP_amplification_2")

    return aggregate_flows

def SSDP_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "1900"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "1900", "src", True, True, "SSDP_amplification")

    return aggregate_flows


def NTP_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # src_port == "123"

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "123", "src", True, True, "NTP_amplification")

    return aggregate_flows

# DONE categories:      22
# IPv4 Protocol 0
# mDNS Reflection/Amplification
# memcached Amplification
# MS SQL RS Amplification
# NetBIOS Reflection/Amplification
# RIPv1 Reflection/Amplification
# rpcbind Reflection/Amplification
# SNMP Amplification
# SSDP Amplification


# TO DO:
# NTP Amplification (Needs packet size)



# PENDING categories:   2
# L2TP Reflection/Amplification (Needs packet size)
# TCP ACK (disabled by default)
