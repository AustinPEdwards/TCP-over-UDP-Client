# AUSTIN EDWARDS
# Class that defines a TCP Segment

from bitstring import Bits, BitArray
import random


class TCPSegment:
    SEGMENT_LEN = 1500 - 20 - 8
    HEADER_WORDS = 5
    HEADER_LEN = HEADER_WORDS * 4
    DATA_LEN = SEGMENT_LEN - HEADER_LEN

    def __init__(self, data, source_port, dest_port, seq_num=0, ack_num=0, window=5808,
                 is_ack=False, is_syn=False, is_fin=False):
        if len(data) > self.DATA_LEN:
            raise ValueError("Data length of " + str(len(data)) + " exceeds max data length of " + str(self.DATA_LEN))
        if source_port >= 65536:
            raise ValueError("Source port of " + str(source_port) + " is too high (max = 65536)")
        if dest_port >= 65536:
            raise ValueError("Destination port of " + str(dest_port) + " is too high (max = 65536)")
        if window >= 65536:
            raise ValueError("Window " + str(window) + " is too high (max = 65536)")
        if source_port < 0 or dest_port < 0 or seq_num < 0 or ack_num < 0 or window < 0:
            raise ValueError("Negative numbers are not allowed")
        self.data = data
        self.source_port, self.dest_port = source_port, dest_port
        self.seq_num, self.ack_num = seq_num % (2**32), ack_num % (2**32)
        self.window = window
        self.is_ack, self.is_syn, self.is_fin = is_ack, is_syn, is_fin

    # Converts packet to bytes
    def to_bytes(self):
        array = BitArray(self.source_port.to_bytes(2, "big") +      # 0-15 bits     0-1 bytes
                         self.dest_port.to_bytes(2, "big") +        # 16-31 bits    2-3 bytes
                         self.seq_num.to_bytes(4, "big") +          # 32-63 bits    4-7 bytes
                         self.ack_num.to_bytes(4, "big") +          # 64-95 bits    8-11 bytes
                         b"\0\0" +                                  # 96-111 bits   12-13 bytes
                         self.window.to_bytes(2, "big") +           # 112-127 bits  14-15 bytes
                         b"\0\0\0\0" +                              # 128-159 bits  16-19 bytes
                         self.data)                                 # 160-          20-   bytes
        array[96:100] = Bits(self.HEADER_WORDS.to_bytes(1, "big"))[4:8]
        array[107], array[110], array[111] = self.is_ack, self.is_syn, self.is_fin
        num = 0
        array[128:144] = Bits(num.to_bytes(2, "big"))
        return array.tobytes()

    # Window Setter
    def set_window(self, window):
        self.window = window
        self.to_bytes()

    # Data Setter
    def set_data(self, data):
        self.data = data
        self.to_bytes()

    # ACK Setter
    def set_ack_num(self, ack_num):
        self.ack_num = ack_num
        self.to_bytes()

    # SEQ Setter
    def set_seq_num(self, seq_num):
        self.seq_num = seq_num
        self.to_bytes()

    # Creates random seq number as required for TCP
    def get_rand_seq_num(self):
        random_number = random.randint(0, 65536)
        return random_number

    # Builds Data Packet
    def build_packet(self, data, dest_port, seq_num, ack_num):
        self.is_syn = False
        self.is_ack = False
        self.is_fin = False
        self.data = data
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        return self.to_bytes()

    # Builds SYN Packet
    def build_SYN_packet(self, seq_num):
        self.is_syn = True
        self.is_ack = False
        self.is_fin = False
        self.seq_num = seq_num
        return self.to_bytes()

    # Builds ACK Packet
    def build_ACK_packet(self, data, seq_num, ack_num, serverport):
        self.is_syn = False
        self.is_ack = True
        self.is_fin = False
        self.data = data
        self.dest_port = serverport
        self.ack_num = ack_num
        self.seq_num = seq_num
        return self.to_bytes()

    # Build FIN Packet
    def build_FIN_packet(self, seq_num, ack_num):
        self.is_syn = False
        self.is_ack = True
        self.is_fin = True
        self.ack_num = ack_num
        self.seq_num = seq_num
        return self.to_bytes()


