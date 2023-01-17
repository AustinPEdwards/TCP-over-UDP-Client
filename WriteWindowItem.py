# AUSTIN EDWARDS
# This class defines the individual window elements
# Contains the packet, a running timer, and whether it has been sent or ACKed

class WriteWindowItem:
    def __init__(self, packet, Time=0, ACKed=False, Sent=False):
        self.packet = packet
        self.Time = Time
        self.ACKed, self.Sent = ACKed, Sent

    def set_ACKed(self):
        self.ACKed = True

    def set_Sent(self, time):
        self.Sent = True
        self.Time = time

