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


Part A Question 1 :
Total TCP Flows Initiated from Seneder 130.245.145.12 are: 3
Explanation : I have unique objects for each tcp flow according to the sport and dport and
    checking whether tcp handshake is successful.

Part A Question 2.a :
I have printed the relative sequence numbers which are easy to read. For this we took the
first sequence number as base. I then matched what should be the ack number for this seq
number and when we received that, that is our result. We printed them for first 2 trasactions
after tcp handshake.
So for connection with srcport 43498, 43500 and 43502, the numbers are same.
We send packet with seq 1 and recieve ack for 25 because the data was of length 24 in this
packet. Next we send packet with seq 25 and we get ack for 1473 becasue the data was of length
1448 in this packet. The MSS is in bytes. The window sacling factor is takin into account for
this which is extracted from options in tcp header. Let it be x, we calculate Winsize * (2 ** x)
to caluclate the receive window size in bytes. Winsize is received in TCp header.

Part A Question 2.b :
For calculating the throughput we took into account the size of complete packet including
the header size and data size. For time we calculated the total time it took from tcp
connection to finish. We calculated throughput from source perspective.
Dividing the total data by total time give out answer for this part.


Part A Question 2.c :
In this we have to calculate the loss rate. So we counted the total number of packets successfully
delivered by checking the syn and ack numbers. Subtracting total success from total packets sent
gives us our loss rate.

Part A Question 2.d :
To calculate this we started with iRTT. After this we made a tuple of ack number required for a syn number
and the TSVal that we get in options field in tcp header from source packet list and made similar tuples
of ack number and TSECR values received from server. So we matched the request and corresponding response
and added the time required in our time. The RTT of lost packets are not taken into account.
Also when single ack is recived for multiple seq the rtt is added only for the packet for which the ack is
received. In the end we calculated the average by dividing by the total successful responses reseived.

The formula we are using to calculate throughput is =
                sq_root(3/2) * ( MSS / (sq_root(p) * RTT))
Using this formula we get throughput of 1.2 MB/sec , 200 KB/sec and infinity throughput respectively for
3 tcp flows. Last is infinity because the loss rate is 0.
Empirical throughput was 5.1 , 1.2 and 1.5 MB/Sec taking into account the header and payload into account.