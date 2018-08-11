High Level View of the analysis_pcap_http Code:

1.) We used dpkt python library to read the pcap file.
2.) We made my own packet class having attributes from TCP header like port numbers,
    seq and ack numbers etc. I parsed these attributes from packet i receieved
    byte by byte and made an object for that packet.
3.) We also exteacted attributes that whether the packet is GET or HTTP by decoding the
    byte starting from data offset field. This is very important to calculate the
    attributes asked in assignment.
4.) The n we sorted these packets according to tcp flows having unique (sport, dport)
    combination and made an object of that tcp connection. This tcp connection class
    has various parametres related to the tcp connection and also have packet list
    from src to dest and dest ot src for that particular tcp flow.
5.) I then used this packet flows to calculate various attributes asked in the question
    which I will be explaining in each part analysis.


Part C Question 1:

Filter Used in WireShark to get the dump is : host sbunetsyslabs.com and Wi-Fi:en0

In http_1080 HTTP/1.0 i used. So for each get request we were getting a new
TCP flow. So as we have already filtered out the packets on sport and dport
basis we had get request and http request for each flow. So as soon as the get
request is fired and then first packet form server comes with "HTTP" response
we started printing out the tuples required for this question. Also
we printed these tuples only for the packet containing data to server the
GET request.


Part C Question 2:
As we have printed the number of tcp flows made for each connection.
We can see the protocol used in http_1080 pcap file is HTTP/1.0.
Because we can see from output a new tcp connection is initiated for
each request. So the total number of connections made were 17 for
17 get requests.

Protocol Used for http_1081.pcap file is HTTP/1.1 because one reason is
the number of tcp flows were 6 which is maximum connections made by chrome
browser for http/1.1. This was also told in class. These were parallel connections
having multiple get request in single tcp flows.

Protocol Used for http_1082.pcap file is HTTP/2.0 because reason is that
the number of tcp flows were 1 which shows that this is persistent connection as
told in class. Only 1 tcp connection was made to serve all the requests. This is
also indicated by the number of packets sent from client side.

Part C Question 3:
Bytes and Packets Sent from client side:
Http 2.0 < HTTP 1.1 < HTTP 1.0
So http 2.0 sends least bytes and packets because only 1 tcp connection is made from
client side. So number of packets sent to make connections and corresponding bytes are
reduced in HTTP 2.0
Opposite is the case for HTTP 1.0 where new connection is made for each GET request.

Time to load the website:
Http 2.0 > HTTP 1.1 > HTTP 1.0
Well going just by the pcap file http 2.0 took most time to load the website and HTTP 1.0
took the least. Actually as we saw in pcap file in both http 1.1 and http 2.0 a couple
of packets having a bare amount of data like 25 bytes were sent after 5 seconds and connections
were also closed after 4-5 seconds. But if we remove those connections close packets the
order changes with :
HTTP 2.0 < HTTP 1.1 < HTTP 1.0