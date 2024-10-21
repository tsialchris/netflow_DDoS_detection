
# Here we define the misuse cases

# Left to implement:
# 

from misuse_processing import get_threshold_and_top_IP_flows
from misuse_processing import get_threshold_and_top_protocol_flows
from misuse_processing import get_threshold_and_top_port_flows


def total_traffic(netflow_flows, number_of_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_IP_flows(netflow_flows, number_of_flows, metric, metric_threshold, True, True)

    return aggregate_flows


def total_UDP_traffic(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "none", True, True)

    return aggregate_flows


def total_TCP_no_flags(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr("........"), True, True)

    return aggregate_flows


def TCP_only_RST(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr(".....R.."), True, True)

    return aggregate_flows


def TCP_only_SYN(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr("......S."), True, True)

    return aggregate_flows


def TCP_only_FIN(netflow_flows, amount_top_flows, metric, metric_threshold):

    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "6", repr(".......F"), True, True)

    return aggregate_flows

def total_DNS(netflow_flows, amount_top_flows, metric, metric_threshold):

    # total traffic with DNS destination port
    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "53", "dst", True, True)

    return aggregate_flows

def total_X_port_destination(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port):

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port, "dst", True, True)

    return aggregate_flows

def total_X_port_source(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port):

    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, protocol, port, "src", True, True)

    return aggregate_flows


def total_ICMP(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "1"
    aggregate_flows = get_threshold_and_top_protocol_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "1", "none", True, True)

    return aggregate_flows

def chargen_amplification(netflow_flows, amount_top_flows, metric, metric_threshold):

    # protocol == "17" (UDP)
    # source_port == "19"
    aggregate_flows = get_threshold_and_top_port_flows(netflow_flows, amount_top_flows, metric, metric_threshold, "17", "19", "src", True, True)
    
    
    return aggregate_flows

def CLDAP_amplification():

    # protocol == "17" (UDP)
    # source_port == "389"

    0 == 0

def DNS_amplification():

    # protocol == "17" (UDP)
    # source_port == "53"

    0 == 0