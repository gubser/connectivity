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
        print("HUHU")
        log.info("new tcp connection".format(self.client_address[0]))
        log.info("recv {} bytes".format(expected_length))
        recvd = self.rfile.read(expected_length)
        if len(recvd) != expected_length:
            log.error("received data not enough")
        
        log.info("send {} bytes".format(expected_length))
        self.wfile.write(self.server.data)
        
        log.info("finished")

class UdpRequest(socketserver.DatagramRequestHandler):
    def handle(self):
        pass
        
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6
    
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        socketserver.TCPServer.server_bind(self)
    
class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    address_family = socket.AF_INET6
    
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        socketserver.UDPServer.server_bind(self)

def start_servers(ports, data):
    logging.info("starting servers...")
    servers = {}
    for port in ports:
        tcp = ThreadingTCPServer(('', port), TcpRequest)
        tcp.data = data
        tcp.listener_thread = threading.Thread(target=tcp.serve_forever, daemon=True)
        tcp.listener_thread.start()
        
        udp = ThreadingUDPServer(('', port), UdpRequest)
        udp.data = data
        udp.listener_thread = threading.Thread(target=udp.serve_forever, daemon=True)
        udp.listener_thread.start()
                
        servers[port] = (tcp, udp)
        
    while True:
        time.sleep(100)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # parse parameters
    parser = argparse.ArgumentParser(description='Provides a server for TCP/UDP/TLS/DTLS/SCTP connectivity testing.')
    parser.add_argument('-f', '--file', default='image.jpg', metavar='filename', help='loads image.jpg from current directory.', type=argparse.FileType('rb'), dest='data')
    parser.add_argument('ports', type=int, metavar='port', nargs='+')

    args = parser.parse_args()
    print(args.ports)
    
    
    # start servers
    start_servers(args.ports, args.data.read())
