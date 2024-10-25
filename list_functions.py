
# find where to append the element and insert it
def find_and_insert(list, metric, element, flag, protocol, port):
    # print(element["proto"], " == ", protocol)
    if (element["proto"] == protocol or protocol == "protocol_irrelevant") and (element["dst_port"] == port or port == "port_irrelevant"):
        # print("element metric: ", int(element[metric]))
        # print("list[i][metric]: ", list[i][metric])
        if flag == "append":
            guard = True
            i = 0
            list_length = len(list)
            # print("list_length ", list_length)
            # parse the list to find if this metric is higher than the other values stored
            while i < list_length:
                # print(i, "---", len(list))
                if element[metric] > list[i][metric]:
                    guard = False
                    list = insert_and_append(list, i, element)
                    break
                # print("---after insert and append--- ", i)
                i = i + 1

            # just append it at the end if it is smaller than the rest
            if guard:
                list.append(element)

            # print("exited while")
            # print(flag)
            # print(len(list))
        # else if flag is "overwrite"
        else:
            i = 0
            while i < len(list):
                if element[metric] > list[i][metric]:
                    insert_and_overwrite(list, i, element)
                    break
                i = i + 1

    return list

# element == flows_per_IP[destination_IP]
# provide the list, the index you want to append to and the element to append
def insert_and_append(list, index, element):
# store the last element of the list in a temp varriable and rotate the list to the right
    temp = list[-1]
    # start from the end of the list
    j = len(list) - 1

    while j > index:
        # print(j, " - " , len(list) - index)
        list[j] = list[j - 1]
        j = j - 1
    list[index] = element
    # break
    list.append(temp)

    # print("--insert_and_append--", index)
    # print("insert and append", len(list))
    return list

def insert_and_overwrite(list, index, element):
    # start from the end of the list
    j = len(list) - 1

    while j > index:
        list[j] = list[j - 1]
        j = j - 1
    list[index] = element
    # break

    # print("--insert_and_overwrite--")

    return list

# check for max
# only used to create the top flows lists
def check_and_insert(top_flows, flow_to_be_added, number_of_flows, metric):

    # top_flows == top_flows
    # port_flow == flow_to_be_added

    # if the list is empty, populate it
    if len(top_flows) < number_of_flows:
        top_flows.append(flow_to_be_added)
        # cannot access self.flows[index].metric, have to use:
        # getattr(self.flows[index], metric)

        # sort the list based on the metric
        # top_flows.sort(key= lambda x : getattr(x, metric))
        top_flows = sorted(top_flows, key=lambda x: getattr(x, metric), reverse=True)
    else:
        # print("IN THE ELSE")
        # find the top values:
        i = 0
        # go through the top_flows, if another value is higher, replace the correct element
        while i < len(top_flows):
            if getattr(flow_to_be_added, metric) > getattr(top_flows[i], metric):
                # print("IN THE IF")
                # print(self.print_top_flows(top_flows, metric))
                insert_and_overwrite(top_flows, i, flow_to_be_added)
                # print(self.print_top_flows(top_flows, metric))
                break
            i = i + 1
    
    return top_flows


def create_sha512_hash(var1, var2, var3):

    import hashlib

    # Concatenate the variables into a single string
    data = f"{var1}{var2}{var3}"
    
    # Encode the string into bytes, required for hashing
    data_bytes = data.encode('utf-8')
    
    # Create SHA-512 hash object
    sha512_hash = hashlib.sha512(data_bytes)
    
    # Return the hexadecimal digest of the hash
    return sha512_hash.hexdigest()


def threshold_check(threshold_flows, flow, metric, metric_threshold, misuse_category_name):
    # check if the metric that interests us is over the set threshold
    if getattr(flow, metric) > metric_threshold:
        threshold_flows[flow.dst4_addr] = flow
        # SEND NOTIFICATIONS HERE

        import logging

        # Configure the logging
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("output.log", mode='a')
                            ])

        # need to create a new hash value for the log (take the existing hash, add the metric and hash again)
        # this is done to differentiate between pps and bps
        log_hash = create_sha512_hash(flow.hash_value, metric, metric)

        logging.info("|| Misuse Category: %s || dst4_addr: %s || metric: %s || threshold: %s || value: %s || Flow ID: %s ||" % 
                        (misuse_category_name, flow.dst4_addr, metric, metric_threshold, getattr(flow, metric), log_hash))

    return threshold_flows



