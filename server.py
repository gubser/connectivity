__author__ = 'Elio Gubser'
import socket
import socketserver
import argparse
import logging
import time

import threading
import ssl
import common

import select

class TcpRequest(socketserver.BaseRequestHandler):
    def handle(self):
        log = logging.getLogger("tcp")

        expected_length = len(self.server.data)
        log.info("new tcp connection".format(self.client_address[0]))

        # check for magic string
        magic_expected = b'happy dance!'
        magic = self.request.recv(len(magic_expected))
        if magic == magic_expected:
            log.info("switching to tls")
            self.request = ssl.wrap_socket(self.request, keyfile='serverkey.pem', certfile='servercert.pem', server_side=True, cert_reqs=ssl.CERT_OPTIONAL, ssl_version=ssl.PROTOCOL_TLSv1_2, ca_certs=None, ciphers='HIGH', do_handshake_on_connect=False)
            self.request.do_handshake()
            recvd_length = 0
        else:
            recvd_length = len(magic)

        # recv image
        log.info("recv {} bytes".format(expected_length))

        start = time.time()
        recvd_length += common.stream_recv(self.request, expected_length-recvd_length, self.server.timeout)
        bitrate = int(recvd_length*8 / (time.time() - start))

        if recvd_length < expected_length:
            log.error("timeout. received data not enough")
        
        # send data
        log.info("send {} bytes with bitrate {} bit/s".format(expected_length, bitrate))
        self.request.setblocking(True)

        common.stream_send_throttled(self.request, bitrate, self.server.data)
        
        log.info("finished")
        self.request.close()
        
class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6
    
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        socketserver.TCPServer.server_bind(self)

class UDPServer:
    def __init__(self, port, data, packet_size=4096, timeout=15):
        self.log = logging.getLogger("udp:{:<6}".format(port))

        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.settimeout(1)
        self.sock.bind(('', port))
        self.port = port
        self.packet_size = packet_size


        self.thread_recv = threading.Thread(target=self._proc, daemon=True)
        self.thread_timeout = threading.Thread(target=self._timeout_proc, daemon=True)

        self.lock = threading.Lock()

        self.data = data
        self.timeout = timeout
        self.requests = {}

    def read_ready(self):
        with self.lock:
            rready, wready, xready = select.select([self.sock.fileno()], [], [])

        return len(rready) > 0

    def start(self):
        self.thread_recv.start()
        self.thread_timeout.start()
        self.log.info("server started")
    
    def issue_send(self, addr):
        t = threading.Thread(target=self._send_proc, args=(addr,))
        t.start()

    def _timeout_proc(self):
        while True:
            time.sleep(1)

            with self.lock:
                toDelete = []
                for key in iter(self.requests):
                    if self.requests[key][1] + self.timeout < time.time():
                        self.log.info("{}: timeout, initiate sending data".format(key))
                        self.issue_send(addr)
                        toDelete.append(addr)

                for key in toDelete:
                    del self.requests[key]

    def _send_proc(self, addr):
        bitrate = int(float(8*self.requests[addr][0]) / (self.requests[addr][1] - self.requests[addr][2]))

        self.log.info("{}: sending data".format(addr))

        common.dgram_send_throttled(self.sock, bitrate, self.data, self.packet_size, addr, self.lock)

        self.log.info("{}: data send complete".format(addr))

    def _recv_proc(self):
        while True:
            if self.read_ready():
                with self.lock:
                    buf, addr = self.sock.recvfrom(self.packet_size)

                    if addr not in self.requests:
                        # add new entry: bytes_received, time last received, time first received
                        self.requests[addr] = [0, 0, time.time()]


                    # reset timeout
                    self.requests[addr][1] = time.time()

                    # record bytes received
                    self.requests[addr][0] += len(buf)

                    self.log.debug("{}: recvd {} of {} bytes ({} %)".format(addr, self.requests[addr][0], len(self.data), self.requests[addr][0]*100/len(self.data)))

                    # all data received? start transmit
                    if self.requests[addr][0] >= len(self.data):
                        self.log.info("{}: recvd full data".format(addr, self.requests[addr][0], len(self.data)))
                        self.perform_send(addr)
                        del self.requests[addr]
            else:
                time.sleep(0.1)
            

def start_servers(ports, data):
    logging.info("starting servers...")
    servers = {}
    for port in ports:
        logging.info("starting tcp port {}".format(port))
        tcp = ThreadingTCPServer(('', port), TcpRequest)
        tcp.data = data
        tcp.timeout = 15
        tcp.listener_thread = threading.Thread(target=tcp.serve_forever, daemon=True)
        tcp.listener_thread.start()

        logging.info("starting udp port {}".format(port))
        udp = UDPServer(port, data)
        udp.start()
                
        servers[port] = (tcp, udp)
        
    while True:
        time.sleep(100)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)-15s %(name)-5s %(levelname)-8s %(message)s')
    
    # parse parameters
    parser = argparse.ArgumentParser(description='Provides a server for TCP/UDP/TLS connectivity testing.')
    parser.add_argument('-f', '--file', default='image.png', metavar='filename', help='loads image.png from current directory.', type=argparse.FileType('rb'), dest='data')
    parser.add_argument('ports', type=int, metavar='port', nargs='+')

    args = parser.parse_args()

    # start servers
    start_servers(args.ports, args.data.read())
