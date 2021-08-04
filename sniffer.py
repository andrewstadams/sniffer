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
            self.IPv4(packet, cur+14)
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

    def IPv4(self, packet:list, cur:int):
        # Header Name
        self.report.append('IPv4', '')
        # Version
        self.report.append('- Version', str(int(packet[cur+0].hexadecimal[0], 16)))
        # Header Length
        self.report.append('- Header Length', str(int(packet[cur+0].hexadecimal[1], 16)))
        # Type of Service
        self.report.append('- Type of Service', '')
        ## Differentiated Services Code Point
        self.report.append('-- Differentiated Services Code Point', '')
        ### Precedence
        temp = int(packet[cur+1].binary[0]+packet[cur+1].binary[1]+packet[cur+1].binary[2], 2)
        if temp == 0:
            self.report.append('--- Precedence', 'Routine')
        elif temp == 1:
            self.report.append('--- Precedence', 'Priority')
        elif temp == 2:
            self.report.append('--- Precedence', 'Immediate')
        elif temp == 3:
            self.report.append('--- Precedence', 'Flash')
        elif temp == 4:
            self.report.append('--- Precedence', 'Flash Override')
        elif temp == 5:
            self.report.append('--- Precedence', 'Critical')
        elif temp == 6:
            self.report.append('--- Precedence', 'Internetwork Control')
        elif temp == 7:
            self.report.append('--- Precedence', 'Network Control')
        else:
            self.report.append('--- Precedence', 'Unregistered')
        ### Delay
        temp = int(packet[cur+1].binary[3], 2)
        if temp == 0:
            self.report.append('--- Delay', 'Normal')
        elif temp == 1:
            self.report.append('--- Delay', 'Low')
        else:
            self.report.append('--- Delay', 'Unregistered')
        ### Throughput
        temp = int(packet[cur+1].binary[4], 2)
        if temp == 0:
            self.report.append('--- Throughput', 'Normal')
        elif temp == 1:
            self.report.append('--- Throughput', 'High')
        else:
            self.report.append('--- Throughput', 'Unregistered')
        ### Reliability
        temp = int(packet[cur+1].binary[5], 2)
        if temp == 0:
            self.report.append('--- Reliability', 'Normal')
        elif temp == 1:
            self.report.append('--- Reliability', 'High')
        else:
            self.report.append('--- Reliability', 'Unregistered')
        ## Explicit Congestion Notification
        self.report.append('-- Explicit Congestion Notification', '')
        ### Reserved
        self.report.append('--- Reserved', packet[cur+1].binary[6]+packet[cur+1].binary[7])
        # Total Length
        self.report.append('- Total Length', str(int(packet[cur+2].binary+packet[cur+3].binary, 2)))
        # Identification
        self.report.append('- Identification', str(int(packet[cur+4].binary+packet[cur+5].binary, 2)))
        # IP Flags
        self.report.append('- IP Flags', '')
        ## Reserved
        self.report.append('-- Reserved', packet[cur+6].binary[0])
        ## Do Not Fragment
        temp = int(packet[cur+6].binary[1], 2)
        if temp == 0:
            self.report.append('-- Do Not Fragment', 'Fragment if necessary')
        elif temp == 1:
            self.report.append('-- Do Not Fragment', 'Do not fragment')
        else:
            self.report.append('-- Do Not Fragment', 'Unregistered')
        ## More Fragments
        temp = int(packet[cur+6].binary[2], 2)
        if temp == 0:
            self.report.append('-- More Fragments', 'This is the last fragment')
        elif temp == 1:
            self.report.append('-- More Fragments', 'More fragments follow this fragment')
        else:
            self.report.append('-- More Fragments', 'Unregistered')
        # Fragment Offset
        self.report.append('- Fragment Offset', str(int(packet[cur+6].binary[3]+packet[cur+6].binary[4]+packet[cur+6].binary[5]+packet[cur+6].binary[6]+packet[cur+6].binary[7]+packet[cur+7].binary, 2)))
        # Time To Live
        self.report.append('- Time To Live', packet[cur+8].decimal)
        # Protocol
        next_protocol = int(packet[cur+9].decimal)
        if next_protocol == 1:
            self.report.append('- Protocol', 'Internet Control Message Protocol version 4 (ICMPv4)')
        elif next_protocol == 6:
            self.report.append('- Protocol', 'Transmission Control Protocol (TCP)')
        elif next_protocol == 17:
            self.report.append('- Protocol', 'User Datagram Protocol (UDP)')
        elif next_protocol == 58:
            self.report.append('- Protocol', 'Internet Control Message Protocol version 6 (ICMPv6)')
        else:
            self.report.append('- Protocol', 'Unregistered')
        # Header Checksum
        self.report.append('- Header Checksum', packet[cur+10].hexadecimal+packet[cur+11].hexadecimal)
        # Source IP Address
        self.report.append('- Source IP Address', packet[cur+12].decimal+'.'+packet[cur+13].decimal+'.'+packet[cur+14].decimal+'.'+packet[cur+15].decimal)
        # Destination IP Address
        self.report.append('- Destination IP Address', packet[cur+16].decimal+'.'+packet[cur+17].decimal+'.'+packet[cur+18].decimal+'.'+packet[cur+19].decimal)
        # Next Protocol
        if next_protocol == 1:
            pass
        elif next_protocol == 6:
            pass
        elif next_protocol == 17:
            pass
        elif next_protocol == 58:
            pass