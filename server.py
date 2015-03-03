import socket
import socketserver
import argparse
import logging
import time

import threading

class TcpRequest(socketserver.StreamRequestHandler):
    def handle(self):
        log = logging.getLogger("tcp")
        
        # recv data
        expected_length = len(self.server.data)
        log.info("new tcp connection".format(self.client_address[0]))
        log.info("recv {} bytes".format(expected_length))
        recvd = self.rfile.read(expected_length)
        if len(recvd) != expected_length:
            log.error("received data not enough")
        
        # send data
        log.info("send {} bytes".format(expected_length))
        self.wfile.write(self.server.data)
        
        log.info("finished")
        
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6
    
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        socketserver.TCPServer.server_bind(self)

class UDPServer:
    def __init__(self, port, ipv6, data, packetSize=4096, timeout=15):
        self.log = logging.getLogger("udp-{}:{:<6}".format("6" if ipv6 else "4", port))
        
        self.ipv6 = ipv6
        self.sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
        self.sock.settimeout(1)
        
        self.data = data
        
        self.sock.bind(('', port))
        self.thread = threading.Thread(target=self._proc, daemon=True)
        
        self.port = port
        self.packetSize = packetSize
        self.timeout = timeout
        self.requests = {}
        
    def start(self):
        self.thread.start()
        self.log.info("server started")
    
    def perform_send(self, addr):
        self.log.info("{}: sending data".format(addr))
        for idx in range(0, len(self.data), self.packetSize):
            packet = self.data[idx:min(idx+self.packetSize, len(self.data))]
            self.sock.sendto(packet, addr)
        self.log.info("{}: data send complete".format(addr))
    
    def _proc(self):
        while True:
            try:
                buf, addr = self.sock.recvfrom(self.packetSize)
            except socket.timeout:
                # check for request timeout, initiate send and remove from requests
                toDelete = []
                for key in iter(self.requests):
                    if self.requests[key][1] + self.timeout < time.time():
                        self.log.info("{}: timeout, initiate sending data".format(key))
                        self.perform_send(addr)
                        toDelete.append(addr)

                for key in toDelete:
                    del self.requests[key]

            else:
                if addr not in self.requests:
                    # add new entry: bytes_received, time last received
                    self.requests[addr] = [0, 0]
                    
                    
                # reset timeout
                self.requests[addr][1] = time.time()
                
                # record bytes received
                self.requests[addr][0] += len(buf)
                
                self.log.debug("{}: recvd {} of {} bytes".format(addr, self.requests[addr][0], len(self.data)))
                
                # all data received? start transmit
                if self.requests[addr][0] >= len(self.data):
                    self.log.info("{}: recvd full data".format(addr, self.requests[addr][0], len(self.data)))
                    self.perform_send(addr)
                    del self.requests[addr]
            
            

def start_servers(ports, data):
    logging.info("starting servers...")
    servers = {}
    for port in ports:
        tcp = ThreadingTCPServer(('', port), TcpRequest)
        tcp.data = data
        tcp.listener_thread = threading.Thread(target=tcp.serve_forever, daemon=True)
        tcp.listener_thread.start()
        
        udp = UDPServer(port, False, data)
        udp.start()
                
        servers[port] = (tcp, udp)
        
    while True:
        time.sleep(100)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)-15s %(name)-5s %(levelname)-8s %(message)s')
    
    # parse parameters
    parser = argparse.ArgumentParser(description='Provides a server for TCP/UDP/TLS/DTLS/SCTP connectivity testing.')
    parser.add_argument('-f', '--file', default='image.png', metavar='filename', help='loads image.png from current directory.', type=argparse.FileType('rb'), dest='data')
    parser.add_argument('ports', type=int, metavar='port', nargs='+')

    args = parser.parse_args()
    print(args.ports)
    
    
    # start servers
    start_servers(args.ports, args.data.read())
