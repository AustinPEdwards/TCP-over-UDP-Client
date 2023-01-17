# AUSTIN EDWARDS
# This is the State Machine used for TCP
# Self Explanatory, based on the TCP Diagram
from statemachine import StateMachine, State

class TCPStateMachine(StateMachine):
    Start = State('Start', initial=True)
    Closed = State('Closed')
    SYNSent = State('SYN_Sent')
    EstablishedRead = State('EstablishedRead')
    EstablishedWrite = State('EstablishedWrite')
    CloseWait = State('CloseWait')
    LastACK = State('LastACK')
    EndConnection = State('EndConnection')
    FINWait1 = State('FINWait1')
    FINWait2 = State('FINWait2')
    Closing = State('Closing')
    TimeWait = State('TimeWait')

    # Handshake
    Start_to_Closed = Start.to(Closed)
    Closed_to_SYNSent = Closed.to(SYNSent)
    # Read and close
    SYNSent_to_EstablishedRead = SYNSent.to(EstablishedRead)
    StayInEstablishedRead = EstablishedRead.to(EstablishedRead)
    EstablishedRead_to_CloseWait = EstablishedRead.to(CloseWait)
    CloseWait_to_LastACK = CloseWait.to(LastACK)
    LastACK_to_EndConnection = LastACK.to(EndConnection)
    # Write and close
    SYNSent_to_EstablishedWrite = SYNSent.to(EstablishedWrite)
    EstablishedWrite_to_FINWait1 = EstablishedWrite.to(FINWait1)

    FINWait1_to_FINWait2 = FINWait1.to(FINWait2)
    FINWait1_to_TimeWait = FINWait1.to(TimeWait)
    FINWait1_to_Closing = FINWait1.to(Closing)
    FINWait2_to_TimeWait = FINWait2.to(TimeWait)
    Closing_to_TimeWait = Closing.to(TimeWait)
    TimeWait_to_EndConnection = TimeWait.to(EndConnection)