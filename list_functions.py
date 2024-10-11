
# find where to append the element and insert it
def find_and_insert(list, metric, element, flag):
    # print("element metric: ", int(element[metric]))
    # print("list[i][metric]: ", list[i][metric])
    if flag == "append":
        guard = True
        i = 0
        list_length = len(list)
        # parse the list to find if this metric is higher than the other values stored
        while i < list_length:
            # print(i, "---", len(list))
            if element[metric] > list[i][metric]:
                guard = False
                list = insert_and_append(list, i, element)
                break
            i = i + 1

        # just append it at the end if it is smaller than the rest
        if guard:
            list.append(element)

        # print("exited while")
        print(flag)
        print(len(list))
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
    diff = len(list) - index - 2
    while j > diff:
        # print(j, " - " , len(list) - index)
        list[j] = list[j - 1]
        j = j - 1
    list[index] = element
    # break
    list.append(temp)

    # print("--insert_and_append--", index)
    print("insert and append", len(list))
    return list

def insert_and_overwrite(list, index, element):
    # start from the end of the list
    j = len(list) - 1
    diff = len(list) - index - 2
    while j > diff:
        list[j] = list[j - 1]
        j = j - 1
    list[index] = element
    # break

    # print("--insert_and_overwrite--")

    return list
