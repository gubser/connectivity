import socket
import argparse
import ipaddress
import logging
import time
#import dtls

class ConnectivityClient:
    def __init__(self, ips, ports, data, udpTimeout=20, udpPacketSize=4096, udp_bitrate=512*1024):
        self.log = logging.getLogger("client")
        self.endpoints = [((ip, port), ipaddress.ip_address(ip).version == 6) for port in ports for ip in ips]
        self.udpTimeout = udpTimeout
        self.udpPacketSize = udpPacketSize
        self.udp_bitrate = udp_bitrate

        self.data = data
        
    def run(self, enable_tcp=None, enable_udp=None, enable_tls=None, enable_dtls=None, enable_sctp=None):

        if enable_tcp is None and enable_udp is None and enable_tls is None and enable_dtls is None and enable_sctp is None:
            # enable all checks if none of them is specified
            enable_tcp = True
            enable_udp = True
            enable_tls = True
            enable_dtls = True
            enable_sctp = True
        else:
            enable_tcp = False if enable_tcp is None else True
            enable_udp = False if enable_udp is None else True
            enable_tls = False if enable_tls is None else True
            enable_dtls = False if enable_dtls is None else True
            enable_sctp = False if enable_sctp is None else True

        for addr, ipv6 in self.endpoints:
            if enable_tcp:
                self.run_tcp(addr, ipv6)
            if enable_udp:
                self.run_udp(addr, ipv6)
            if enable_tls:
                pass#self.run_tls(addr, ipv6)
            if enable_dtls:
                pass#self.run_dtls()
            if enable_sctp:
                pass#self.run_sctp()
            
    def run_tcp(self, addr, ipv6):
        self.log.info("tcp {}: [1/4] connecting...".format(addr))

        sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

        try:
            sock.connect(addr)
        except OSError as e:
            self.log.error("tcp {}: [*/4] connection failed: {}".format(e.strerror))
        else:
            self.log.info("tcp {}: [2/4] sending...".format(addr))
            sock.send(self.data)
            self.log.info("tcp {}: [3/4] receiving...".format(addr))
            sock.recv(len(self.data))
            self.log.info("tcp {}: [4/4] send & receive successful.".format(addr))
        finally:
            sock.close()
    
    def run_udp(self, addr, ipv6):
        self.log.info("udp {} [1/3]: sending... ".format(addr))

        # calculate delay between packets
        delay = self.udpPacketSize*8 / self.udp_bitrate
        self.log.debug("udp {} [1/3]: sending with bitrate {} bit/s and packet size {} bytes. calculated delay between packets: {}s".format(addr, self.udp_bitrate, self.udpPacketSize, delay))

        sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        for idx in range(0, len(self.data), self.udpPacketSize):
            packet = self.data[idx:min(idx+self.udpPacketSize, len(self.data))]
            sock.sendto(packet, addr)
            time.sleep(delay)

        self.log.info("udp {} [2/3]: send complete, receiving...".format(addr))
        recvd_length = 0
        try:
            last_time = time.time()
            sock.settimeout(1)
            while recvd_length < len(self.data):
                if last_time + self.udpTimeout < time.time():
                    raise TimeoutError
                try:
                    recv_data, recv_addr = sock.recvfrom(self.udpPacketSize)
                except socket.timeout:
                    pass
                else:
                    last_time = time.time()
                    recvd_length += len(recv_data)
        except TimeoutError:
            self.log.info("udp {} [3/3]: timeout on recv, got {} of {} bytes ({} %)".format(addr, recvd_length, len(self.data), recvd_length*100/len(self.data)))
        else:
            self.log.info("udp {} [3/3]: recv complete.".format(addr))
        
        sock.close()
        
    
    def run_tls(self, addr, ipv6):
        raise NotImplemented()
        
        self.log.info("send image to {} over tls".format(addr))
        

def main():
    logging.basicConfig(level=logging.DEBUG)
    
    # parse parameters
    parser = argparse.ArgumentParser(description='Provides a client for TCP/UDP/TLS/DTLS/SCTP connectivity testing.')
    parser.add_argument('-f', '--file', default='image.png', metavar='filename', help='loads image.png from current directory.', type=argparse.FileType('rb'), dest='data')
    parser.add_argument('--no-tcpdump-check', action='store_true', dest='no_tcpdump_check')
    parser.add_argument('--hosts', metavar='hostname/ip', type=str, nargs='+', required=True, dest='hosts')
    parser.add_argument('--ports', metavar='port', type=int, nargs='+', required=True, dest='ports')
    parser.add_argument('--udp-bitrate', type=str, default='1M', metavar='bitrate', help='set maximum udp bitrate. use postfix M and k to specify megabits or kilobits (e.g. 500k)', dest='udp_bitrate')

    parser_tcp = parser.add_mutually_exclusive_group()
    parser_tcp.add_argument('--tcp', action='store_true', dest='enable_tcp')
    parser_tcp.add_argument('--no-tcp', action='store_false', dest='enable_tcp')

    parser_udp = parser.add_mutually_exclusive_group()
    parser_udp.add_argument('--udp', action='store_true', dest='enable_udp')
    parser_udp.add_argument('--no-udp', action='store_false', dest='enable_udp')

    parser_tls = parser.add_mutually_exclusive_group()
    parser_tls.add_argument('--tls', action='store_true', dest='enable_tls')
    parser_tls.add_argument('--no-tls', action='store_false', dest='enable_tls')

    parser.set_defaults(enable_tcp=None, enable_udp=None, enable_tls=None, enable_dtls=None, enable_sctp=None)

    args = parser.parse_args()

    # parse bitrate
    if args.udp_bitrate[-1] == 'M':
        udp_bitrate = int(args.udp_bitrate[0:-1])*1000000
    elif args.udp_bitrate[-1] == 'k':
        udp_bitrate = int(args.udp_bitrate[0:-1])*1000
    else:
        udp_bitrate = int(args.udp_bitrate)

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
            try:
                infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
            except socket.gaierror as e:
                logging.error("skipping {}: {}".format(host, e.strerror))
            else:
                ips.append( infos[0][4][0] )
        else:
            ips.append(host)
        
    cc = ConnectivityClient(ips, args.ports, args.data.read(), udp_bitrate=udp_bitrate)
    cc.run(enable_tcp=args.enable_tcp, enable_udp=args.enable_udp, enable_tls=args.enable_tls, enable_dtls=args.enable_dtls, enable_sctp=args.enable_sctp)

if __name__ == "__main__":
    main()
