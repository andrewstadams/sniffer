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
        elif next_protocol == '86DD':
            self.report.append('- EtherType', 'Internet Protocol version 6 (IPv6)')
        else:
            self.report.append('- EtherType', 'Unregistered')