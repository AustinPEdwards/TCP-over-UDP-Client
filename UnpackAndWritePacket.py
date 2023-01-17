# AUSTIN EDWARDS
# Contains several functions that manipulate packets

# unpacks a data packet and returns relevant fields
def unpack_data(packet):
    serverSeqNum = int.from_bytes((packet[4], packet[5], packet[6], packet[7]), "big")
    serverAckNum = int.from_bytes((packet[8], packet[9], packet[10], packet[11]), "big")
    window = int.from_bytes((packet[14], packet[15]), "big")
    data = bytearray()

    j = 20
    while j < len(packet):
        data.append(packet[j])
        j = j + 1

    return serverSeqNum, serverAckNum, window, data, (len(packet)-20)    # data and dataLength


# writes data to file
def write_data_to_file(filename, data):
    if len(data) == 0:
        with open(filename,"ba") as file_object:
            file_object.close()
    else:
        with open(filename, "ba") as file_object:
            file_object.write(data)
    file_object.close()
    return


# unpacks ACK and returns relevant fields
def unpack_ack(packet):
    serverSeqNum = int.from_bytes((packet[4], packet[5], packet[6], packet[7]), "big")
    serverAckNum = int.from_bytes((packet[8], packet[9], packet[10], packet[11]), "big")
    window = int.from_bytes((packet[14], packet[15]), "big")
    return serverSeqNum, serverAckNum, window # data and dataLength

