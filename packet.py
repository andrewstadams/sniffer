from collections import namedtuple

Byte = namedtuple('Byte', ['character', 'decimal', 'binary', 'hexadecimal'])

class Packet:

    def __init__(self):
        self.packet = list()

    def get(self):
        return self.packet

    def append(self, chr:str):
        self.packet.append(Byte(chr, str(ord(chr)), format(ord(chr),'b').zfill(8), format(ord(chr),'X').zfill(2)))

    def clear(self):
        self.packet.clear()