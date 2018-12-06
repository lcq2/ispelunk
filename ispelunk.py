import socket
import struct
import io

class ISpelunkClient:
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

    def hexDump(self, data, address, fmt):
        FormatData = {
            'b': (16, 'B', '%02x', 1),
            'w': (16, '<H', '%04x', 2),
            'd': (8, '<I', '%08x', 4),
            'q': (4, '<Q', '%016x', 8)
        }
        dataview = io.BytesIO(data)
        datalen = len(data)
        while dataview.tell() != datalen:
            toget = FormatData[fmt][0]
            line = "%016x: " % address
            address += toget*FormatData[fmt][3]
            dump = list()
            for i in range(toget):
                x = dataview.read(FormatData[fmt][3])
                if len(x) > 0:
                    x = struct.unpack(FormatData[fmt][1], x)
                    dump.append(FormatData[fmt][2] % x)
            if len(dump) > 0:
                line += ' '.join(dump)
            print(line)

    def readMemory(self, address, length):
        msg = struct.pack("<BQI", ord('r'), address, length)
        self._sock.sendall(msg)
        stream = io.BytesIO()
        bytesWritten = 0
        while bytesWritten < length:
            bytesWritten += stream.write(self._sock.recv(4096))
        return stream.getvalue()

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
    
