'''
AUSTIN EDWARDS
CSCE 365 COMPUTER NETWORKS ASSIGNMENT 2: TCP OVER UDP USING SELECTIVE REPEAT
'''
import argparse
import socket
import time
import TCPSegment
import WriteWindowItem
import struct
from UnpackAndWritePacket import *
from bitstring import Bits, BitArray
import TCP_StateMachine

'''
ARGPARSE

FORMAT:
    1.	‘-a’ is for IP Addresses,
    2.	‘-sp’ for server port
    3.	‘-f’ for file name,
    4.	‘-p’ for port numbers
    5.	‘-m’ for mode (r = read from server, w = write to server)

Example: python3 trivialftp.py -a 234.45.345.2 -sp 50001 -p 50000 -f mytext.txt -m w
'''
parser = argparse.ArgumentParser(description='Communicate Via TFTP')
parser.add_argument('-a', '--address', help='IP Address', required=True)
parser.add_argument('-sp', '--serverport', type=int, help='Server Port', required=True)
parser.add_argument('-cp', '--clientport', type=int, help='Port Number', required=True)
parser.add_argument('-f', '--filename', type=str, help='File Name', required=True)
parser.add_argument('-m', '--mode', type=str, help='Mode: r = read from server, w = write to server', required=True)
args = parser.parse_args()
if args.mode != 'r' and args.mode != 'w':
    print("Invalid mode: Must use 'r' for Read or 'w' for Write")
    exit()
elif args.serverport < 5000 or args.serverport > 65535 or args.clientport < 5000 or args.clientport > 65535:
    print("Port numbers must be between 5000 and 65,535")
    exit()
elif args.filename.endswith('/'):
    print("Must have file name")
    exit()

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientSocket.bind(('', args.clientport))
clientSocket.settimeout(1)

# long list of global variables
clientSeqNum = 0
clientAckNum = 0
serverSeqNum = 0
serverAckNum = 0
dataLength = 0
window = 1500

receivedPacket = bytearray()

WRITE_WINDOW = []
READ_WINDOW = []
STORE_DATA_WINDOW = []
REMAINING_WINDOW = 0
FIRST_PACKET = True
END_FILE = False
FIRST_WRITE_DATA = True
FIRST_READ_DATA = True
FOUND_PACKET = False
ALL_PACKETS_ACKED = False
FIRST_WINDOW = True
DATA_LENGTH = 1452
SEQ_NUM = 0
ACK_NUM = 0
Last_Packet_of_Handshake = 0

LAST_TIMEOUT_PACKET = 0
TIMEOUT_COUNT = 0


# These first several functions are used in READ mode, It is a purely UDP send->receive system
# I could not get the server to respect my window in READ mode

# Sends Single Packet to Server
def do_sendPacket(sendPacket):
    clientSocket.sendto(sendPacket.to_bytes(), (args.address, args.serverport))
    print('SENDING:       ACK = ' + str(sendPacket.ack_num) + '     SEQ = ' + str(sendPacket.seq_num))
    return sendPacket


# If the condition that the last 2 received packets are the same
# Sends previous packet to server and calls the "do_receivePacket" function
def do_resendPacket(receivedPacket, prevReceivedPacket, prevSentPacket):
    if receivedPacket == prevReceivedPacket:
        print("======== RESENDING =========")
        prevSentPacket = do_sendPacket(prevSentPacket)
        receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
    return receivedPacket, prevSentPacket


# Receives packet from the server and checks via "do_resendPacket"
# implements socket.timeout with some conditions upon timeout
def do_receivePacket(prevSentPacket, prevReceivedPacket):
    global FIRST_PACKET
    global TIMEOUT_COUNT
    global LAST_TIMEOUT_PACKET
    while True:
        try:
            receivedPacket, serverAddress = clientSocket.recvfrom(2048)
            (serverSeqNum, serverAckNum, window) = unpack_ack(receivedPacket)
            print('RECEIVING:     SEQ = ' + str(serverSeqNum) + '     ACK = ' + str(serverAckNum))
            (receivedPacket, prevSentPacket) = do_resendPacket(receivedPacket, prevReceivedPacket, prevSentPacket)
            break
        except socket.timeout:
            print("====== SOCKET TIMEOUT =======")
            # limits the number of timeouts to 4, closes socket, and exits
            if LAST_TIMEOUT_PACKET == prevSentPacket:
                TIMEOUT_COUNT += 1
            if TIMEOUT_COUNT == 3:
                clientSocket.close()
                exit()
            LAST_TIMEOUT_PACKET = prevSentPacket

            # if the first packet received from the server is lost, set window to the expected 5808
            # limits unnecessary errors from the server during drop and latency tests
            if FIRST_PACKET:
                prevSentPacket.set_window(5808)
                FIRST_PACKET = False

            # if the timeout limit hasn't been met, send the previous packet again
            prevSentPacket = do_sendPacket(prevSentPacket)
    return receivedPacket


# The next couple functions are for the WRITE mode.  This mode is correctly in Selective Repeat
# Periodically checks if any of the packets within the window have had a timeout
def Packet_Timeout():
    # loops through window
    for obj in WRITE_WINDOW:
        # if any packets have been sent and have a running timer of over 0.5s, resend
        if obj.Sent and (time.time() - obj.Time) > .5:
            print("====== PACKET TIMEOUT =======")
            # ACK_NUM += 1
            # obj.packet.set_ack_num(ACK_NUM)
            clientSocket.sendto(obj.packet.to_bytes(), (args.address, args.serverport))
            print("SENDING:     ACK = " + str(obj.packet.ack_num) + '     SEQ = ' + str(obj.packet.seq_num))
            obj.set_Sent(time.time())
    return


# Checks Window for packets when received from the server
# Will ack even if out of order
def Check_Window(serverSeqNum, serverAckNum):
    global FOUND_PACKET
    # loops through window
    for obj in WRITE_WINDOW:
        # if found expected packet
        if obj.packet.ack_num == serverSeqNum:
            obj.set_ACKed()
            FOUND_PACKET = True
            break
    # if packet was found in window, ack all previous packets
    if FOUND_PACKET:
        for obj in WRITE_WINDOW:
            if obj.packet.ack_num < serverSeqNum:
                obj.set_ACKed()
                return
    # if the packet wasn't found, resend packet
    else:
        Resend_Window_Packet(serverAckNum)
    return


# Resends the expected packet from the window
def Resend_Window_Packet(serverAckNum):
    print("======== RESENDING =========")
    for obj in WRITE_WINDOW:
        if obj.packet.seq_num == serverAckNum:
            print('SENDING:       ACK = ' + str(obj.packet.ack_num) + '     SEQ = ' + str(obj.packet.seq_num))
            clientSocket.sendto(obj.packet.to_bytes(), (args.address, args.serverport))
            obj.set_Sent(time.time())
            break
    return


# Receives ACK or Timeout: Timeouts are very rare and will cause the program to exit,
# since the timeouts are done manually and individually for each packet in the window
# as required by selective repeat
def Receive_ACK_Packet():
    global FOUND_PACKET
    global REMAINING_WINDOW
    FOUND_PACKET = False
    try:
        receivedPacket, serverAddress = clientSocket.recvfrom(2048)
        (serverSeqNum, serverAckNum, window) = unpack_ack(receivedPacket)
        print('RECEIVING:     SEQ = ' + str(serverSeqNum) + '     ACK = ' + str(serverAckNum))
        Check_Window(serverSeqNum, serverAckNum)
    except socket.timeout:
        print("====== SOCKET TIMEOUT =======")
        clientSocket.close()
        exit()
    return


# sends "unsent" packets in the window
def Send_Window():
    for obj in WRITE_WINDOW:
        if obj.Sent is False:
            print('SENDING:       ACK = ' + str(obj.packet.ack_num) + '     SEQ = ' + str(obj.packet.seq_num))
            clientSocket.sendto(obj.packet.to_bytes(), (args.address, args.serverport))
            obj.set_Sent(time.time())
    return

# Fills the window, calls add_packet_to_window() until full or-end of-file
def Fill_Write_Window():
    while END_FILE is False:  # while there is still data in the file
        while REMAINING_WINDOW != 0 and DATA_LENGTH == 1452:  # fill server window with max data from file
            Add_Packet_to_Window()
        break
    return


# creates packet and appends to window
def Add_Packet_to_Window():
    global REMAINING_WINDOW
    global END_FILE
    global DATA_LENGTH
    global SEQ_NUM
    global ACK_NUM
    # if you can add a full packet to the window, read 1452 bytes of data
    if REMAINING_WINDOW >= 1500:
        data_write = file_object.read(1452)
        # if less than 1452 bytes are read, we know our file is done
        if len(data_write) < 1452:
            END_FILE = True
    # if the window is too full to fill a packet
    else:
        # fill the remaining window (less than 1452 bytes)
        data_write = file_object.read(REMAINING_WINDOW)
        # if the length of data < than the remaining window, the file is done
        if len(data_write) < (REMAINING_WINDOW):
            END_FILE = True
    # update some global variables
    DATA_LENGTH = len(data_write)
    REMAINING_WINDOW -= DATA_LENGTH
    # create packet
    Packet = TCPSegment.TCPSegment(data_write, args.clientport, args.serverport)
    # accordingly chose the packet type (first, middle, last -> ACK, DATA, FIN)
    if END_FILE:
        Packet.build_FIN_packet(SEQ_NUM, ACK_NUM)
        TCP_DFA.EstablishedWrite_to_FINWait1()
    elif FIRST_WRITE_DATA:
        Packet.build_ACK_packet(data_write, SEQ_NUM, ACK_NUM, args.serverport)
    elif not FIRST_WRITE_DATA:
        Packet.build_packet(data_write, args.serverport, SEQ_NUM, ACK_NUM)
    # set the window size in the packet
    Packet.set_window(window)
    # append the packet to the window
    WRITE_WINDOW.append(WriteWindowItem.WriteWindowItem(Packet))
    SEQ_NUM += DATA_LENGTH  # increment SEQ_NUM and ACK_NUM
    ACK_NUM += 1
    return


# prints window so you can see Selective Repeat working
def print_window(Window):
    print("WINDOW:  ")
    for obj in Window:
        print(str(obj.packet.ack_num) + " " + str(obj.packet.seq_num) + " ACKed " + str(obj.ACKed) + " Sent " + str(obj.Sent) + " Time "+ str(float(f'{(time.time() - obj.Time):.2f}')))
    return


# MAIN FUNCTION - looks gross, I know.  First time programming in python + using the statemachine library
# couldn't figure out how to perform functions on statr changes so everything is in a large loop
# Essentially, while not in the final state -> enter into if-else to find correct TCP state
# Hideous, but it works
if __name__ == '__main__':
    # initialize state machine
    TCP_DFA = TCP_StateMachine.TCPStateMachine()
    while not TCP_DFA.is_EndConnection:
        if TCP_DFA.is_Start:
            TCP_DFA.Start_to_Closed()

        # State "Closed": initiates connection with SYN packet and sends to "SYN Sent"
        elif TCP_DFA.is_Closed:
            print('\nSTATE = CLOSED')
            sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
            clientSeqNum = sendPacket.get_rand_seq_num()
            sendPacket.build_SYN_packet(clientSeqNum)
            prevSentPacket = do_sendPacket(sendPacket)
            TCP_DFA.Closed_to_SYNSent()

        # State "SYN Sent": receives first packet from server and sends to "Established Read" or "Established Write"
        elif TCP_DFA.is_SYNSent:
            print('\nSTATE = SYN_SENT')
            receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
            # if in READ mode
            if args.mode == 'r':
                # first packet in READ mode can contain data, write to file
                (serverSeqNum, serverAckNum, window, data, dataLength) = unpack_data(receivedPacket)
                write_data_to_file(args.filename, data)
                messageBits = BitArray(receivedPacket)
                # if the packet is an ACK SYN send ACK to establish handshake and send to "Established Read"
                if messageBits[107] and messageBits[110]:
                    sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
                    sendPacket.build_ACK_packet(bytearray(), clientSeqNum + 1, serverSeqNum + 1, args.serverport)
                    prevSentPacket = do_sendPacket(sendPacket)
                    TCP_DFA.SYNSent_to_EstablishedRead()
                    REMAINING_WINDOW = window
                    print('\nSTATE = ESTABLISHED READ')
            # if in WRITE mode
            elif args.mode == 'w':
                (serverSeqNum, serverAckNum, window) = unpack_ack(receivedPacket)
                messageBits = BitArray(receivedPacket)
                # if the packet is an ACK SYN, send to "Established Read"
                if messageBits[107] and messageBits[110]:
                    TCP_DFA.SYNSent_to_EstablishedWrite()

        # READ MODE:
        # State "Established Read": THIS IS WHERE DATA TRANSFER HAPPENS
        elif TCP_DFA.is_EstablishedRead:
            # Receive first data
            receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
            (serverSeqNum, serverAckNum, window, data, dataLength) = unpack_data(receivedPacket)
            # Write data to file
            write_data_to_file(args.filename, data)
            if FIRST_READ_DATA:
                ACK_NUM = serverSeqNum + dataLength
                FIRST_READ_DATA = False
            else:
                ACK_NUM += dataLength
            # build and sent next ack packet
            sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
            sendPacket.build_ACK_packet(bytearray(), serverAckNum + 1, ACK_NUM, args.serverport)
            prevSentPacket = do_sendPacket(sendPacket)
            messageBits = BitArray(receivedPacket)
            # if the previous data packet is a fin, send to "Close Wait"
            if messageBits[111]:
                TCP_DFA.EstablishedRead_to_CloseWait()
            # if the previous data packet is purely data, stay in "Established Read"
            else:
                TCP_DFA.StayInEstablishedRead()

        # State "Close Wait": send FIN packet and send to "Last ACK"
        elif TCP_DFA.is_CloseWait:
            print('\nSTATE = CLOSE WAIT')
            sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
            sendPacket.build_FIN_packet(serverAckNum + 2, serverSeqNum + 1)
            prevSentPacket = do_sendPacket(sendPacket)
            TCP_DFA.CloseWait_to_LastACK()

        # State "Last ACK":  Receive last ACK and send to "End Connection"
        elif TCP_DFA.is_LastACK:
            print('\nSTATE = LAST ACK')
            receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
            (serverSeqNum, serverAckNum, window, data, dataLength) = unpack_data(receivedPacket)
            messageBits = BitArray(receivedPacket)
            if messageBits[107]:
                TCP_DFA.LastACK_to_EndConnection()

        # MODE WRITE:
        # State "Established Write": THIS IS WHERE DATA TRANSFER HAPPENS
        elif TCP_DFA.is_EstablishedWrite:
            # set timeout to 5 since this will not be used (individual timers)
            clientSocket.settimeout(5)
            print('\nSTATE = ESTABLISHED WRITE')
            prev_dataLength = 0
            dataLength = 1452  # 1452
            firstData = True
            endFile = False
            # set window to only accept the first packet
            # this way the handshake is guaranteed to be completed
            if window > 1452:
                REMAINING_WINDOW = 1452
            else:
                REMAINING_WINDOW = window
            SEQ_NUM = serverAckNum
            ACK_NUM = serverSeqNum + 1
            FIRST_WRITE_DATA = True
            # opens the file to begin reading
            with open(args.filename, "br") as file_object:
                # Sending first packet to complete handshake
                Fill_Write_Window()
                print_window(WRITE_WINDOW)
                prevSentPacket = do_sendPacket((WRITE_WINDOW[0]).packet)
                # receive first ack
                receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
                WRITE_WINDOW.pop(0)
                FIRST_WRITE_DATA = False
                # Sending full window
                REMAINING_WINDOW = window
                Fill_Write_Window()
                Send_Window()
                print_window(WRITE_WINDOW)
                # do while the window has packets and while the file is open
                while WRITE_WINDOW or not END_FILE:
                    # manually check window for timeouts
                    Packet_Timeout()
                    # receive ACKs
                    Receive_ACK_Packet()
                    # if the first packet in the window is ACKed, increase the window and pop repeatedly
                    while WRITE_WINDOW and (WRITE_WINDOW[0]).ACKed:
                        REMAINING_WINDOW = REMAINING_WINDOW + len((WRITE_WINDOW[0]).packet.data)
                        WRITE_WINDOW.pop(0)
                    # Re-Fill the Window
                    Fill_Write_Window()
                    # Send the Window
                    Send_Window()
                    print_window(WRITE_WINDOW)

                file_object.close()

        # State "FIN Wait 1": receive either a FIN+ACK, ACK, or FIN and send to according state
        elif TCP_DFA.is_FINWait1:
            print('\nSTATE = FIN WAIT 1')
            SEQ_NUM += DATA_LENGTH  # increment SEQ_NUM and ACK_NUM
            ACK_NUM += 1
            messageBits = BitArray(receivedPacket)
            if messageBits[107] and messageBits[111]:  # if received FIN + ACK
                sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
                sendPacket.build_ACK_packet(bytearray(), SEQ_NUM, ACK_NUM, args.serverport)
                sendPacket.set_window(window)
                prevSentPacket = do_sendPacket(sendPacket)
                TCP_DFA.FINWait1_to_TimeWait()

            elif messageBits[107] and not messageBits[111]:  # if ACK
                TCP_DFA.FINWait1_to_FINWait2()

            elif messageBits[111] and not messageBits[107]:  # if ACK
                sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
                sendPacket.build_ACK_packet(bytearray(), SEQ_NUM, ACK_NUM, args.serverport)
                sendPacket.set_window(window)
                prevSentPacket = do_sendPacket(sendPacket)
                TCP_DFA.FINWait1_to_Closing()

        # State "FIN Wait 2": receive ACK, send ACK, and send to "Time Wait"
        elif TCP_DFA.is_FINWait2:
            print('\nSTATE = FIN WAIT 2')
            receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
            (serverSeqNum, serverAckNum, window) = unpack_ack(receivedPacket)
            sendPacket = TCPSegment.TCPSegment(bytearray(), args.clientport, args.serverport)
            sendPacket.build_ACK_packet(bytearray(), serverAckNum + 1, serverSeqNum + 1, args.serverport)
            sendPacket.set_window(window)
            prevSentPacket = do_sendPacket(sendPacket)
            TCP_DFA.FINWait2_to_TimeWait()

        # State "Closing": receive last ack and send to "Time Wait"
        elif TCP_DFA.is_Closing:
            print('\nSTATE = CLOSING')
            receivedPacket = do_receivePacket(prevSentPacket, receivedPacket)
            (serverSeqNum, serverAckNum, window) = unpack_ack(receivedPacket)
            TCP_DFA.Closing_to_TimeWait()

        # State "TimeWait": I'm not waiting since it just adds time when running tests
        # send immediately to "End Connection"
        elif TCP_DFA.is_TimeWait:
            print('\nSTATE = TIME WAIT')
            TCP_DFA.TimeWait_to_EndConnection()

clientSocket.close()
