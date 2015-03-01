# TCP/UDP/TLS/DTLS/SCTP connectivity testing tool

## Measurement Setup
The measurement will be performed by a selected group of test persons that are advised to run a (small) python/c tool on a computer connected to the Internet over their private home gateway or potentially the enterprise network of their employers (if not prohibited).

The tool will test the connectivity to four selected server hosted by the commercial VM provider Digital Ocean, in Amsterdam, London, New York, and Singapore.

## Measurement Methodology
The measurement tool consist of a client and server functionality.

The client should send a selected image file to a server based on a provided list of IP addresses and respective port numbers. The client sends the file multiple time by using each time a different transport protocol/capability (in the order as listed in the title).

The server must listen for any kind of connection on a given list of port numbers. The server will receive the file and send its local copy of the same file back using the same transport protocol (within the same connection in case of TCP and then closes the connection in case of TCP).

The measurement tool should write a tracefile documenting the timestamp and other end's IP address every time a file is send or received. To map the sender-side trace to the receiver-side trace we, for now, assume that the timestamp and IP address will be sufficient. However, if a large number of measurements are performed simultaneously and some of the clients are NAT'ed this might not be the case anyway.

## Measurement Evaluation
The trace file will be used for an initial (manual) assessment of the dependency of connectivity on the used transport protocol.

In parallel to the running the actual measurement tool a pcap trace should be recorded using tcpdump (the measurement tool might want to check that tcpdump is running). This trace will subsequently be used to perform offline analysis using QoF. Of particular interest are the number of packets sent and received, as well as the exact timing of the first and last packet of a file transmission. Based on this information the number of losses (or receptively retransmission in TCP) can be calculated as well as the average sending rate which might give hinds on different treatment of the transport protocols under test in the network.


