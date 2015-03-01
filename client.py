import socket
import argparse
import ipaddress
import logging
#import dtls

class ConnectivityClient:
    def __init__(self, ips, ports, data, udp_timeout=20):
        self.log = logging.getLogger("client")
        self.endpoints = [((ip, port), ipaddress.ip_address(ip).version == 6) for port in ports for ip in ips]
        self.udp_timeout = udp_timeout
        
        self.data = data
        
    def run(self):
        for addr, ipv6 in self.endpoints:
            self.run_tcp(addr, ipv6)
            self.run_udp(addr, ipv6)
            self.run_tls(addr, ipv6)
            #self.run_dtls()
            #self.run_sctp()
            
    def run_tcp(self, addr, ipv6):
        self.log.info("send image to {} over tcp".format(str(addr)))
        
        sock = None
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.connect(addr)
        sock.send(self.data)
        sock.recv(len(self.data))
        sock.close()
        
    
    def run_udp(self, addr, ipv6):
        self.log.info("send image to {} over udp".format(addr))
    
    def run_tls(self, addr, ipv6):
        self.log.info("send image to {} over tls".format(addr))
        

def main():
    logging.basicConfig(level=logging.INFO)
    
    # parse parameters
    parser = argparse.ArgumentParser(description='Provides a client for TCP/UDP/TLS/DTLS/SCTP connectivity testing.')
    parser.add_argument('-f', '--file', default='image.jpg', metavar='filename', help='loads image.jpg from current directory.', type=argparse.FileType('rb'), dest='data')
    parser.add_argument('--no-tcpdump-check', action='store_true', dest='no_tcpdump_check')
    parser.add_argument('--hosts', metavar='hostname/ip', type=str, nargs='+', required=True, dest='hosts')
    parser.add_argument('--ports', metavar='port', type=int, nargs='+', required=True, dest='ports')

    args = parser.parse_args()
    
    
    # check for running tcpdump
    if not args.no_tcpdump_check:
        import psutil
        if 'tcpdump' not in [str(p.name) for p in psutil.process_iter()]:
            raise Exception('No tcpdump process is running. To skip this check, use "--no-tcpdump-check".')
    
    # lookup hostnames
    ips = []
    for host in args.hosts:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET6)
            if len(infos) == 0:
                logging.error("couldn't resolve {}".format(host))
            else:
                ips.append( infos[0][4][0] )
        else:
            ips.append(host)
        
    cc = ConnectivityClient(ips, args.ports, args.data.read())
    cc.run()

if __name__ == "__main__":
    main()
