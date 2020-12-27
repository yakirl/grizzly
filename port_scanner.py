import datetime
import psutil
import ipaddress
from netaddr import *
import queue
import traceback
import threading
import socket
from scapy.all import *


OUTPUT_FILE = "scanner.log"
# 0 - INFO, 1 - DEBUG
LOG_LVL = 0

def output(msg, lvl=0):
    if lvl > LOG_LVL:
        return
    print(msg)
    msg += "\n"
    with open(OUTPUT_FILE, "a") as f:
        f.write(msg)

class PortType:
    TCP = "tcp"
    UDP = "udp"

'''
Object for one-time scan
 Find all available IPs from all network interfaces and scan all common TCP and UDP ports
    According to defined rules (follow nmap behavior)
'''
class IPScanner(object):
    NUM_WORKERS = 30
    TIMEOUT = 2
    ICMP_TIMESTAMP_REQUEST_TRUNCATED = bytes.fromhex('0d00f2ff00000000')
    PORTS = []
    LOOPBACK = '127.0.0.1'
    EXCLUDE_INTERFACES = ['docker0']
    UDP_SCAN = True

    def __init__(self):
        self.work_queue = queue.Queue()
        self.set_ports_to_scan()
        self.ip_to_open_ports = {}
        self.terminate = False
        with open(OUTPUT_FILE, "w") as f:
            f.write(datetime.now().strftime("%H:%M:%S") + "\n")

    def set_ports_to_scan(self):
        with open("common_ports.txt", "r") as f:
            ports_str = f.read()
            ports_str = ports_str.strip()
            tmp_list = sum(((list(range(*[int(j) + k for k,j in enumerate(i.split('-'))]))
                                                            if '-' in i else [int(i)]) for i in ports_str.split(',')), [])
            IPScanner.PORTS = list(set(tmp_list))


    '''
    use host discovery same as nmap, as descibed here: https://pentest-tools.com/blog/nmap-port-scanner/
    flags codes can be found here: https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy
    '''
    @staticmethod
    def check_host_responsive(host_ip):
        output("Checking if host %s is responsive" % host_ip, lvl=1)
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host_ip), timeout=IPScanner.TIMEOUT, verbose=0)
        if len(ans) > 0 and ans[0][1].psrc == host_ip:
            return True
        p = sr1(IP(dst=host_ip)/ICMP()/"XXXXXX", timeout=IPScanner.TIMEOUT, verbose=0)
        if p is not None:
            if ICMP in p and p[ICMP].type != 3:
                return True
        p = sr1(IP(dst=host_ip)/TCP(dport=443,flags="S"), timeout=IPScanner.TIMEOUT, verbose=0)
        if p is not None:
            if ((0x04 & p.getlayer("TCP").flags) == 0x04) or ((0x10 & p.getlayer("TCP").flags) == 0x10):
                return True
        p = sr1(IP(dst=host_ip)/TCP(dport=80,flags="A"), timeout=IPScanner.TIMEOUT, verbose=0)
        if p is not None:
            if ((0x04 & p.getlayer("TCP").flags) == 0x04):
                return True
        if sr1(IP(dst=host_ip)/ICMP(IPScanner.ICMP_TIMESTAMP_REQUEST_TRUNCATED)/"XXXXXX", timeout=IPScanner.TIMEOUT, verbose=0) is not None:
            return True
        return False

    @staticmethod
    def check_open_tcp_port(host_ip, port):
        p = sr1(IP(dst=host_ip)/TCP(dport=port,flags="S"), timeout=IPScanner.TIMEOUT, verbose=0)
        if p is not None and ((0x10 & p.getlayer("TCP").flags) == 0x10) and ((0x04 & p.getlayer("TCP").flags) != 0x04):
            return True
        return False

    @staticmethod
    def check_open_udp_port(host_ip, port):
        p = sr1(IP(dst=host_ip)/UDP(dport=port), timeout=IPScanner.TIMEOUT, verbose=0)
        if p is not None and ((p[ICMP].type == 3) and (p[ICMP].code in [1,2,3,9,10,13])):
            return False
        return True

    '''
    Scanning TCP by SYN stealth to all defined ports of the given host
    Scanning UDP by sending packets and check that no ICMP unreachable response has been recieved
            see https://nmap.org/book/scan-methods-udp-scan.html
    '''
    @staticmethod
    def scan_ports(ip):
        open_ports = []
        for port in IPScanner.PORTS:
            if IPScanner.check_open_tcp_port(ip, port):
                open_ports.append((PortType.TCP, port))
            if IPScanner.UDP_SCAN:
                if IPScanner.check_open_udp_port(ip, port):
                    open_ports.append((PortType.UDP, port))
        return open_ports

    def scan_host(self):
        while True:
            try:
                if self.terminate:
                    return
                ip = self.work_queue.get(timeout=3)
                # Special case for localhost. scapy only see packets on wire
                if ip == socket.gethostbyname('localhost'):
                    output("localhost")
                    self.ip_to_open_ports[ip] = []
                    for port in IPScanner.PORTS:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            res = sock.connect_ex(('localhost', port))
                            if res == 0:
                                output("localhost port %s is open" % port)
                                self.ip_to_open_ports[ip].append((PortType.TCP, port))
                    continue
                elif not IPScanner.check_host_responsive(ip):
                    continue
                output("%s: Host %s is alive. scanning ports..." % (threading.get_ident(), ip))
                self.ip_to_open_ports[ip] = IPScanner.scan_ports(ip)
                output("%s: Host %s: found %d open ports..." % (threading.get_ident(), ip, len(self.ip_to_open_ports[ip])))
            except queue.Empty:
                if self.load_done:
                    return
            except Exception as e:
                self.terminate = True
                traceback.print_exc()

    '''
    TODO: filter pseudo interfaces
    '''
    @staticmethod
    def get_addr_cidrs():
        addr_cidrs = []
        if_addrs = psutil.net_if_addrs()

        for interface in if_addrs.keys():
            if interface in IPScanner.EXCLUDE_INTERFACES:
                continue
            for addr in if_addrs[interface]:
                try:
                    if addr.address == IPScanner.LOOPBACK:
                        continue
                    # check valid IPv4 address and mask
                    ip_valid = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",addr.address)
                    net_valid = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",addr.netmask)
                    if ip_valid is None or net_valid is None:
                        continue
                    net_bits = sum(bin(int(x)).count('1') for x in addr.netmask.split('.'))
                    addr_cidr = '%s/%s' % (addr.address, net_bits)
                    addr_cidrs.append(addr_cidr)
                except:
                    continue
        return addr_cidrs

    def report(self):
        output("*** Report ***")
        for ip in self.ip_to_open_ports.keys():
            output("Open ports for IP %s:" % ip)
            for (port_type, port) in self.ip_to_open_ports[ip]:
                output("** %s %s" % (port_type, port))
            output(" ----- ")

    def scan(self):
        self.load_done = False
        addr_cidrs = IPScanner.get_addr_cidrs()
        threads = []
        output("Spawning workers...")
        for worker in range(IPScanner.NUM_WORKERS):
           t = threading.Thread(target = self.scan_host)
           t.daemon = True
           t.start()
           threads.append(t)

        output("Filling work queue...")
        self.work_queue.put(IPScanner.LOOPBACK)
        for addr_cidr in addr_cidrs:
            output("scanning Subnet %s" % addr_cidr)
            ip_list = list(IPNetwork(addr_cidr))
            for ip in ip_list:
                self.work_queue.put(ip.format())

        output("finished sending jobs")
        while True:
            if self.terminate or self.work_queue.empty():
                break
        output("All jobs done. finishing...")
        self.load_done = True
        for t in threads:
            t.join()


def main():
    scanner = IPScanner()
    scanner.scan()
    scanner.report()

if "__main__" == __name__:
    main()
