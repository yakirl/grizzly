import datetime
from netaddr import *
import threading
from scapy.all import *



def output(msg):
    msg += "\n"
    print(msg)
    with open("output.txt", "a") as f:
        f.write(msg)


class AttackType(object):
    TCP_SYN = "tcp-syn"
    TCP_SYN_ACK = "tcp-syn-ack"
    ICMP_SMURF = "icmp-smurf"
    ICMP_POD = "icmp-pod"


class Attack(object):
    def __init__(self, _type, _time, data={}):
        self.type = _type
        self.time = _time
        self.data = data


class Detector(object):

    def __init__(self, proto, insertion_func, analyzer_func):
        self.proto = proto
        self.packets = []
        self.insertion = insertion_func
        self.analyze = analyzer_func

'''
PortDetector
 Detect various types of attacks on the network:
    TCP SYN flooding: mass SYN packets to overload half open connections
    TCP SYN-ACK flooding: when attacker spoof this IP and using SYN flood on 3rd server. The attack exhaust
            system resources while trying to figure what sequence this packet belong to (tables lookups)
    ICMP-SMURF: DDoS attack in which the attacker flood the network with ICMP request with this spoofed IP so all responses
            are sent to this machine
    ICMP-POD: attack in which attacker send malformed or oversized ICMP packets to exploit vulnerability

 Every INTERVAL, spawn detector-threads, one for each threat, to sniff relevant packets for SNIFF_PERIOD
    then analyze the data to figure if we got suspicious activity

'''

class PortDetector(object):
    INTERVAL = 60
    SNIFF_PERIOD = 10
    BUFFER_SIZE = 1024
    ATTACK_INTERVAL = 2
    ATTACK_NUM_PACKETS = 20
    MAX_ICMP_PAYLOAD = 1024

    def __init__(self):
        self._stop = False
        self.attack_interval = PortDetector.ATTACK_INTERVAL
        self.max_raw = PortDetector.MAX_ICMP_PAYLOAD
        self.attacks = []
        self.detector_data = {
            AttackType.TCP_SYN:     Detector("tcp", lambda pkt: TCP in pkt and pkt[TCP].flags.flagrepr() == "S", self.tcp_syn_analyze),
            AttackType.TCP_SYN_ACK: Detector("tcp", lambda pkt: TCP in pkt and pkt[TCP].flags.flagrepr() == "SA", self.tcp_syn_ack_analyze),
            AttackType.ICMP_SMURF:  Detector("icmp", lambda pkt: ICMP in pkt, self.icmp_smurf_analyze),
            AttackType.ICMP_POD:    Detector("icmp", lambda pkt: ICMP in pkt, self.icmp_pod_analyze)
        }
        self.ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3]==conf.iface][0]
        self.mac = get_if_hwaddr(conf.iface)
        with open("output.txt", "w") as f:
            f.write(datetime.now().strftime("%H:%M:%S") + "\n")

    def calc_stream_avg(self, pkt_list):
        return (pkt_list[-1].time - pkt_list[0].time) / len(pkt_list)

    def is_high_activity(self, pkt_list):
        if len(pkt_list) > PortDetector.ATTACK_NUM_PACKETS:
            return self.calc_stream_avg(pkt_list) < self.attack_interval
        return False

    '''
    4 handlers for handling the data received. analyze each by the properties of each attack
    We look for large number of packets sent on a small window, to detect susipicious DDoS attacks
    '''
    def tcp_syn_analyze(self):
        ip_to_pkts = {}
        for pkt in self.detector_data[AttackType.TCP_SYN].packets:
            if IP in pkt:
                if pkt[IP].src not in ip_to_pkts.keys():
                    ip_to_pkts[pkt[IP].src] = [pkt]
                else:
                    ip_to_pkts[pkt[IP].src].append(pkt)

        for ip in ip_to_pkts.keys():
            if self.is_high_activity(ip_to_pkts[ip]):
                self.attacks.append(Attack(AttackType.TCP_SYN, datetime.now(), {"ip": ip}))

    def tcp_syn_ack_analyze(self):
        packets = [pkt for pkt in self.detector_data[AttackType.TCP_SYN_ACK].packets if IP in pkt and pkt[IP].src != self.ip]
        if self.is_high_activity(packets):
            self.attacks.append(Attack(AttackType.TCP_SYN_ACK, datetime.now()))

    def icmp_smurf_analyze(self):
        smurf_list = [pkt for pkt in self.detector_data[AttackType.ICMP_SMURF].packets if (Ether in pkt and pkt[Ether].src != self.mac) and
                                                                                           (IP in pkt and pkt[IP].src == self.ip)]
        if self.is_high_activity(smurf_list):
            self.attacks.append(Attack(AttackType.ICMP_SMURF, datetime.now()))

    '''
    Max size for IP packet is 65535 however. A larger payload sits in fragmented packets can cause overflow.
    Typical ICMP payload is 56 bytes however. But no reason to add payload to ICMP so we set here a limit of 1024
    '''
    def icmp_pod_analyze(self):
        pod_list = [pkt for pkt in self.detector_data[AttackType.ICMP_POD].packets if Raw in pkt and len(pkt[Raw].load) > self.max_raw]
        if self.is_high_activity(pod_list):
            self.attacks.append(Attack(AttackType.ICMP_POD, datetime.now()))

    def report(self):
        if self.attacks != []:
            output("Found attacks:")
        for attack in self.attacks:
            output("%s: %s. %s" % (attack.time, attack.type, attack.data))
        output("-------- ")

    def stop(self):
        self._stop = True

    def analyze_data(self):
        for detector in self.detector_data.keys():
            self.detector_data[detector].analyze()
            self.detector_data[detector].packets = []


    def sniff(self, attack_type):
        def insert_packet(_attack_type):
            def insert(pkt):
                if len(self.detector_data[_attack_type].packets) == PortDetector.BUFFER_SIZE:
                    return
                if self.detector_data[_attack_type].insertion(pkt):
                    self.detector_data[_attack_type].packets.append(pkt)
            return insert
        func = insert_packet(attack_type)
        sniff(filter=self.detector_data[attack_type].proto,
              prn=func,
              timeout=PortDetector.SNIFF_PERIOD)

    def detect(self):
        threads = []
        output("Spawning sniffers...")
        for detector in self.detector_data.keys():
           t = threading.Thread(target = self.sniff, args=(detector,))
           t.daemon = True
           t.start()
           threads.append(t)
        output("Spawn done. waiting to finish...")
        for t in threads:
            t.join()
        output("detectors joined")
        self.analyze_data()
        self.report()
        self.attacks = []

    def start(self):
        while True:
            if self._stop:
                break
            start_time = time.time()
            self.detect()
            duration = time.time() - start_time
            output("took %d seconds" % duration)
            sleep_time = PortDetector.INTERVAL - duration
            if sleep_time > 0:
                time.sleep(sleep_time)



def main():
    detector = PortDetector()
    t = threading.Thread(target = detector.start)
    t.daemon = True
    t.start()
    time.sleep(PortDetector.INTERVAL*8)
    detector.stop()

if "__main__" == __name__:
    main()
