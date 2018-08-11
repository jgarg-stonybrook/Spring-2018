High Level View of the analysis_pcap_tcp Code:

1.) We used dpkt python library to read the pcap file.
2.) We made my own packet class having attributes from TCP header like port numbers,
    seq and ack numbers etc. I parsed these attributes from packet i receieved
    byte by byte and made an object for that packet.
3.) Then we sorted these packets according to tcp flows having unique (sport, dport)
    combination and made an object of that tcp connection. This tcp connection class
    has various parametres related to the tcp connection and also have packet list
    from src to dest and dest ot src for that particular tcp flow.
4.) I then used this packet flows to calculate various attributes asked in the question
    which I will be explaining in each part analysis.

Part B Question 1 :
We calculated the congestion window size at sender side which I will explain here.
Example Result:
Format : Window Size BY Packets, Window Size BY Bytes
Congestion windows for 43498 TCP Flow :
Congestion Window : 10 13716
Congestion Window : 20 30280
Congestion Window : 33 49962
Congestion Window : 45 68130
Congestion Window : 67 101438
Congestion Window : 100 151400
Congestion Window : 135 204390
Congestion Window : 203 307342
Congestion Window : 271 410294
Congestion Window : 407 616198

So the first one is initial congestion window.
Method: We calculated the total number of packets sent by the sender to receiver before it
waits for an ack and gets it. After this we reset the size of our congestion window and
start counting the again the packets sent before next ack of the packet that is sent
after the congestion window is resetted. The ack received for packets sent in previous
congestion window is not taken into account becasue they are ack for previous window.
So we can see after sending 20 more packets we recived an ack, so the size of next congestion
window is 20. So we can see the window size increased quite rapidly in starting in slow start
phase. Similarly we calculated the next 10 congestion window size. If we print
the congestion window sizes for all windows we see that at later stage the cwnd increased
at very very less rate and sometimes get decreased also.
We did this at sender side because to use the ack number to reset the window size when an
ack is received.

Part B Question 2 :
We have calculated the packet re transmissions at sender side because we received triple
duplicate acks at sender side. So to calculate the triple ack loss we counted the ack number
that we are getting and if that count becomes 4 and the sender send that packet again, we
counted that as 1 retransmission due to triple duplicate ack also called as fast retransmissions.
Also we already calculated the total packet retransmissions. So we subtracted fast retransmissions
from total to calculate the transmissions due to timeout. Also we calculated the tcp out of order
as retransmissions becasue as analyzed from wireshark those packets were sent twice from sender side
without any triple dup acks.