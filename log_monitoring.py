
# I need a new output.log every 5 minutes (or every x interval of time) for this to work correctly

from log_monitoring_objects import Flow_Tracker

from log_monitoring_functions import line_splitter

f = open("./output.log", "r")

lines = f.readlines()

f.close()

monitored_flows = {}

# how many repetitions are needed to trigger an alert
repetition_threshold = 5

for line in lines:
    
    # 2024-10-25 10:45:30,779 - INFO - || Misuse Category: total_traffic || dst4_addr: 212.205.221.3 || metric: bps || threshold: 100000 || value: 1336629 || Flow ID: 2dd147dc8aeb119f2d94f2f8186502c7bacffe8687457d76e56a5d6de34a60314584a6aa8571be2eeedf7d149d0e66515c600ddc619bcd553942aaee71b196aa ||
    
    if "Flow ID" in line:

        flow_ID = line_splitter(line, "Flow ID")
        # print(flow_ID)

        misuse_category = line_splitter(line, "Misuse Category")
        # print(misuse_category)

        dst4_addr = line_splitter(line, "dst4_addr")

        metric = line_splitter(line, "metric")

        metric_threshold = line_splitter(line, "threshold")

        value = line_splitter(line, "value")


        # if this flow_ID is not present in monitored_flows, add it
        if not (flow_ID in monitored_flows):
            monitored_flows[flow_ID] = Flow_Tracker(flow_ID, misuse_category, dst4_addr, 
                                                    metric, metric_threshold, value)
        else:
            monitored_flows[flow_ID].increment_active_counter()
            monitored_flows[flow_ID].isActive = True

    # if we spot "END OF INTERVAL", make all flows inactive,
    # purge any flows that are not active (and are below the threshold for alert triggering)
    elif "END OF INTERVAL" in line:
        # this for loop is written like this to be able to delete items during the iteration itself
        # otherwise you get a runtime error
        # it represents:
        # for flow_ID in monitored_flows:
        for flow_ID in list(monitored_flows.keys()):
            # print(monitored_flows[flow_ID])
            if monitored_flows[flow_ID].isActive:
                monitored_flows[flow_ID].isActive = False

            # else, purge
            else:
                if monitored_flows[flow_ID].active_counter < repetition_threshold:
                    del monitored_flows[flow_ID]

# SEND NOTIFICATIONS HERE
import logging

# Configure the logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("alerts.log", mode='a')
                    ])

for flow_ID in monitored_flows:
    flow = monitored_flows[flow_ID]
    logging.warning("|| Misuse Category: %s || dst4_addr: %s || metric: %s || threshold: %s || value: %s || Flow ID: %s ||" % 
                    (flow.misuse_category, flow.dst4_addr, flow.metric, flow.metric_threshold, flow.value, flow.flow_ID))
    


f = open("./alerts.log", "a")
f.write("==================================================END OF ALERTS INTERVAL==================================================\n")
f.close()
