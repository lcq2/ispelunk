import socket
import struct

class ISpelunkClient:
    ItemsPerLine = {
        'b': 16,
        'w': 16,
        'd': 8,
        'q': 4,
        'p': 4
    }
    def __init__(self, host = "localhost", port = 31337):
        self._host = host
        self._port = port
        try:
            self._sock = socket.socket()
            self._sock.connect((self._host, self._port))
            data = self._sock.recv(16)
            self._kernelBase, self._kaslr = struct.unpack("QQ", data)
        except socket.error as err:
            print("Cannot connect to server: %s" % (err))
            raise err
        except struct.error as err:
            print("Could not decode hello cmd arguments: %s" % (err))
            raise err

    def close(self):
        self._sock.close()

    @staticmethod
    def hexDump(data, offset, fmt):
        dataview = memoryview(data)
        datalen = len(data)
        for i in range(0, datalen, 16):
            hexData = ' '.join(["%02x" % b for b in dataview[i:(i+16)]])

    def readMemory(self, address, length):
        msg = struct.pack("<BQI", ord('r'), address, length)
        self._sock.sendall(msg)
        
    @property
    def port(self):
        return self._port

    @property
    def host(self):
        return self._host
    
    @property
    def kernelBase(self):
        return self._kernelBase

    @property
    def kaslr(self):
        return self._kaslr

    def __repr__(self):
        return "kernelBase: 0x%16x - kaslr: 0x%08x" % (self._kernelBase, self._kaslr)
    
