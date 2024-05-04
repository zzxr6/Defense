# Jacob Latonis
import sys
import dpkt
import binascii
import socket

portscan_attempts = {}  # key = destination IP address -> value is everything else
non_handshake_syn_flood = {}  # key = destination IP addres -> value is everything else
exclude = []  # Sujay said once per host -> https://piazza.com/class/k02myt46eko5qq?cid=143

# hex of IP : decimal of ip
ip = ["c0:a8:00:64", "c0:a8:00:67", "c0:a8:00:01"]
mac = ["7c:d1:c3:94:9e:b8", "d8:96:95:01:a5:c9", "f8:1a:67:cd:57:6e"]


def addSemiColon(str):
    if (len(str) == 8):
        return str[:2] + ':' + str[2:4] + ":" + str[4:6] + ':' + str[6:8]
    if (len(str) == 12):
        return str[:2] + ':' + str[2:4] + ":" + str[4:6] + ':' + str[6:8] + ':' + str[8:10] + ':' + str[10:12]


def testFlood(ethData, IP, timeStamp, pktCount):
    if (socket.inet_ntoa(ethData.dst)) in exclude:
        return

    dstIPandPort = socket.inet_ntoa(ethData.dst) + "port" + str(IP.dport)
    if dstIPandPort in non_handshake_syn_flood:
        packets = non_handshake_syn_flood[dstIPandPort]
        while len(packets) > 0:
            current_packet = packets[0]
            if timeStamp - current_packet['timeStamp'] > 1:
                packets = packets[1:len(packets)]
            else:
                break
        packets.append({'source': ethData.src, 'destination': socket.inet_ntoa(ethData.dst), 'timeStamp': timeStamp,
                        'packetNum': pktCount})
        if len(packets) > 100:
            exclude.append(socket.inet_ntoa(ethData.dst))
            print("SYN floods!")
            print("IP: " + str(socket.inet_ntoa(ethData.dst)))
            print("Packet number: " + str([packet['packetNum'] for packet in packets])[1:-1])
            packets = []
    else:
        non_handshake_syn_flood[dstIPandPort] = [
            {'source': ethData.src, 'destination': socket.inet_ntoa(ethData.dst), 'timeStamp': timeStamp,
             'packetNum': pktCount}]


def testPS(IP, port, pktCount):
    destination = IP.dst
    if destination in portscan_attempts:
        attempts = portscan_attempts[destination]
        for attempt in attempts:
            if port == attempt['destinationPort']:
                return
        attempts.append({'source': IP.src, 'destination': destination, 'destinationPort': port, 'packetNum': pktCount})
    else:
        portscan_attempts[destination] = [
            {'source': IP.src, 'destination': destination, 'destinationPort': port, 'packetNum': pktCount}]


def testARP(ethData, pktCount):
    IP = addSemiColon(binascii.hexlify(ethData.spa))
    if IP in ip:
        index = ip.index(IP)
        # print(addSemiColon(binascii.hexlify(ethData.sha)))
        if mac[index] != addSemiColon(binascii.hexlify(ethData.sha)):
            print("ARP Spoofing!")
            print("MAC: " + mac[index] + "")
            print("Packet Number: " + str(pktCount))


if (len(sys.argv) != 2):
    print("Usage: python scanner.py example.pcap")
file = open(sys.argv[1], 'rb')
pcap = dpkt.pcap.Reader(file)
num = 1

for (ts, buf) in pcap:
    ethLayer = dpkt.ethernet.Ethernet(buf)
    ethData = ethLayer.data
    if (ethLayer.type == int(0x0806)):
        testARP(ethData, num)
    elif (ethLayer.type == int(0x0800)):
        # print("IPv4")
        ipData = ethData.data
        # if tcp or udp
        # check portscan in both udp and tcp
        if type(ipData) is dpkt.tcp.TCP:
            # check syn flood in tcp handshakes
            if ipData.flags == 2:
                testPS(ethData, ipData.dport, num)
                testFlood(ethData, ipData, ts, num)
        if type(ipData) is dpkt.udp.UDP:
            testPS(ethData, ipData.dport, num)
    num += 1

for destination in portscan_attempts:
    attempts = portscan_attempts[destination]
    if len(attempts) >= 100:
        print("Port scan!")
        # how to print ip properly?
        print(socket.inet_ntoa(attempts[0]['destination']))
        # print(attempts[0]['destination'])
        print("Packet number: " + str([attempt['packetNum'] for attempt in attempts])[1:-1])
