from packet import Packet
from report import Report

class Sniffer:

    def __init__(self):
        self.packet = Packet()
        self.report = Report()

    def get_packet(self):
        return self.packet.get()

    def get_report(self):
        return self.report.get()

    def run(self, path:str):
        # Reset
        self.packet.clear()
        self.report.clear()
        # Read Packet
        with open(path, 'rb') as file:
            while byte := file.read(1):
                self.packet.append(str(byte, 'latin-1'))
        # Create Report
        self.report.append('File Path', path)
        self.Ethernet(self.get_packet(), 0)

    def Ethernet(self, packet:list, cur:int):
        # Header Name
        self.report.append('Ethernet', '')
        # Destination MAC Address
        self.report.append('- Destination MAC Address', packet[cur+0].hexadecimal+':'+packet[cur+1].hexadecimal+':'+packet[cur+2].hexadecimal+':'+packet[cur+3].hexadecimal+':'+packet[cur+4].hexadecimal+':'+packet[cur+5].hexadecimal)
        # Source MAC Address
        self.report.append('- Source MAC Address', packet[cur+6].hexadecimal+':'+packet[cur+7].hexadecimal+':'+packet[cur+8].hexadecimal+':'+packet[cur+9].hexadecimal+':'+packet[cur+10].hexadecimal+':'+packet[cur+11].hexadecimal)
        # EtherType
        next_protocol = packet[cur+12].hexadecimal+packet[cur+13].hexadecimal
        if next_protocol == '0800':
            self.report.append('- EtherType', 'Internet Protocol version 4 (IPv4)')
        elif next_protocol == '0806':
            self.report.append('- EtherType', 'Address Resolution Protocol (ARP)')
            self.ARP(packet, cur+14)
        elif next_protocol == '86DD':
            self.report.append('- EtherType', 'Internet Protocol version 6 (IPv6)')
        else:
            self.report.append('- EtherType', 'Unregistered')

    def ARP(self, packet:list, cur:int):
        # Header Name
        self.report.append('ARP', '')
        # Hardware Type
        temp = int(packet[cur+0].binary+packet[cur+1].binary, 2)
        if temp == 1:
            self.report.append('- Hardware Type', 'Ethernet (10Mb)')
        elif temp == 2:
            self.report.append('- Hardware Type', 'Experimental Ethernet (3Mb)')
        else:
            self.report.append('- Hardware Type', 'Unregistered')
        # Protocol Type
        temp = packet[cur+2].hexadecimal+packet[cur+3].hexadecimal
        if temp == '0800':
            self.report.append('- Protocol Type', 'Internet Protocol version 4 (IPv4)')
        elif temp == '0806':
            self.report.append('- Protocol Type', 'Address Resolution Protocol (ARP)')
        elif temp == '86DD':
            self.report.append('- Protocol Type', 'Internet Protocol version 6 (IPv6)')
        else:
            self.report.append('- Protocol Type', 'Unregistered')
        # Hardware Address Length
        self.report.append('- Hardware Address Length', packet[cur+4].decimal)
        # Protocol Address Length
        self.report.append('- Protocol Address Length', packet[cur+5].decimal)
        # Operation Code
        temp = int(packet[cur+6].binary+packet[cur+7].binary, 2)
        if temp == 1:
            self.report.append('- Operation Code', 'ARP Request')
        elif temp == 2:
            self.report.append('- Operation Code', 'ARP Reply')
        else:
            self.report.append('- Operation Code', 'Unregistered')
        # Sender Hardware Address
        self.report.append('- Sender Hardware Address', packet[cur+8].hexadecimal+':'+packet[cur+9].hexadecimal+':'+packet[cur+10].hexadecimal+':'+packet[cur+11].hexadecimal+':'+packet[cur+12].hexadecimal+':'+packet[cur+13].hexadecimal)
        # Sender Protocol Address
        self.report.append('- Sender Protocol Address', packet[cur+14].decimal+'.'+packet[cur+15].decimal+'.'+packet[cur+16].decimal+'.'+packet[cur+17].decimal)
        # Target Hardware Address
        self.report.append('- Target Hardware Address', packet[cur+18].hexadecimal+':'+packet[cur+19].hexadecimal+':'+packet[cur+20].hexadecimal+':'+packet[cur+21].hexadecimal+':'+packet[cur+22].hexadecimal+':'+packet[cur+23].hexadecimal)
        # Target Protocol Address
        self.report.append('- Target Protocol Address', packet[cur+24].decimal+'.'+packet[cur+25].decimal+'.'+packet[cur+26].decimal+'.'+packet[cur+27].decimal)