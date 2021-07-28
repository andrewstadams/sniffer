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