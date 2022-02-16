#UDP but its actually UDP and not a UDP stream like the TCP impersonating skrub they are

#packet formats (assuming MTU is 512):

#encrypted packet format:
#
# 2 byte contact id 
# 4 byte unit index (nonce)
# - 502 byte encrypted chunk:
#       2 byte blake2b checksum
#       500 byte data
#

#special packet format (GENERIC)
#
# 2 byte id == 0 #special
# 2 byte id #actual id
# 504 byte data chunk
#

#new contact packet format
#
# 2 byte id == 0
# 2 byte id == 0
# 32 byte public key
# signed chunk
#   2 byte remote id
#   1 byte send return (0 for need, 1 for have) #! Consider removing
#   2 byte local id (only when returning)
#

#new data send packet format
#
# 2 byte id == 0
# 2 byte id ==  > 0
# 504 byte encrypted chunk:
#   2 byte blake2b checksum
#   1 byte type == 0
#   20 byte nonce prefix
# 20 byte nonce prefix

#data miss request
#
# 2 byte id == 0
# 2 byte id == > 0
# 504 bytes encrypted chunk:
#   2 byte blake2b checksum
#   1 byte type == 1
#   20 byte nonce prefix
#   - 4 byte index chunks
#

#kill contact request
#
# 2 byte id == 0
# 2 byte id == > 0
# encrypted chunk:
#   2 byte blake2b checksum
#   1 byte type == 2
#    

import socket
import socketserver
import threading
import ipaddress
from nacl.exceptions import BadSignatureError
import nacl.utils
import nacl.secret
from nacl.hash import blake2b
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey

BYTE_ORDER = 'big'
TEST_ADDRESS = ('127.0.0.1', 9193)
TEST_FILE = 'lol.txt'

#socket class used to send data
class Usocket:

    init = False
    contacted = False
    r_id = 0
    nonce = 0
    box = None

    def __init__(s, address, receive_id, private_key, nonce_pre=0, mtu=512):
        
        s.address = address
        s.mtu = mtu
        s.sk = private_key
        s.pk = private_key.public_key
        s.l_id = receive_id
        s.nonce_pre = nonce_pre

        if len(address) == 2:
            s.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif len(address) == 4:
            s.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            raise TypeError('Expected a tuple of size 2 or 4 for address')

        s.contact(True)

    def contact(s, returner):
        #send new contact
        id = b'\x00\x00' #special 0 id
        real_id = b'\x00\x00' #special 0 real id
        sign_key = SigningKey(s.private_key)
        pk = sign_key.verify_key.__bytes__() #public key in bytes

        local_id = s.l_id.to_bytes(2, byteorder=BYTE_ORDER, signed=False) #receive id

        if returner:
            send_return = b'\x00' #we want id of peer
        else:
            send_return = b'\x01' #we have id of peer

        #sign id for verification
        unsigned = local_id + send_return
        signed = sign_key.sign(unsigned) 

        #concat data
        data = id + real_id + pk + signed

        #send contact packet and await return
        s.socket.sendto(data, s.address)

    def reinit(s):

        if not s.contacted:
            print('A contact has not been acheived for this peer yet')
            return

        print('Initilizing a new data send with a bumped nonce')
        
        #init new data send
        id = b'\x00\x00' #special 0 id
        remote_id = s.r_id.to_bytes(2, byteorder=BYTE_ORDER, signed=False) #actual id since special id is in use
        header = id + remote_id

        s.nonce_pre += 1
        nonce_pre = s.nonce_pre.to_bytes(20, byteorder=BYTE_ORDER, signed=False)

        #type 0 for new data send
        type = b'\x00'

        #checksum
        check = blake2b(type + nonce_pre, digest_size=2, person=remote_id) 

        #encrypt data for validation
        data = check + type + nonce_pre
        cipher = s.box.encrypt(data, nonce_pre + b'\x00\x00\x00\x00')

        packet = header + cipher + nonce_pre

        s.socket.sendto(packet, s.address)

    def send(s):

        if not s.contacted:
            print('A contact has not been acheived for this peer yet')
            return

        if not s.init:
            s.reinit()
        
    def close(s):
        
        id = b'\x00\x00' #special 0 id
        remote_id = s.r_id.to_bytes(2, byteorder=BYTE_ORDER, signed=False) #actual id since special id is in use
        header = id + remote_id

        type = b'\x02'
        nonce_pre = s.nonce_pre.to_bytes(20, byteorder=BYTE_ORDER, signed=False)

        #checksum
        check = blake2b(type, digest_size=2, person=remote_id)

        data = check + type
        cipher = s.box.encrypt(data, nonce_pre + b'\x00\x00\x00\x00')

        packet = header + cipher
        s.socket.sendto(packet, s.address)

        s.socket.close()
        
#socketserver class used to receive and respond to data
class Ulisten(socketserver.ThreadingMixIn, socketserver.UDPServer):    
    pass

class handler(socketserver.BaseRequestHandler):

    #handle data accordingly. Format is [data, socket] for udp
    def handle(self):

        unit = self.request[0]
        socket = self.request[1]

        #decontruct contact id header
        id = int.from_bytes(unit[0:2], byteorder=BYTE_ORDER, signed=False)
        
        #special id = 0 packet handling
        if id == 0:
            real_id = int.from_bytes(unit[2:4], byteorder=BYTE_ORDER, signed=False)

            #new contact packet
            if real_id == 0:
                
                key = unit[4:38]
                signed = unit[38:]

                new_id = len(contacts)

                #verify signed data
                vk = VerifyKey(key)
                try:
                    chunk = vk.verify(signed)
                except BadSignatureError:
                    print('A contact packet was invalid')
                    return

                remote_id = int.from_bytes(chunk[0:2], byteorder=BYTE_ORDER)
                send_return = chunk[2:3]
                local_id = int.from_bytes(chunk[3:5], byteorder=BYTE_ORDER)

                c = contacts[local_id]
                c.r_id = remote_id
                c.contacted = True

                if send_return == b'\x00':
                    #send return contact
                    c.contact(False)

            else:
                pass

        #regular data packet
        else:
            index = int.from_bytes(unit[2:6], byteorder=BYTE_ORDER, signed=False)

def start():
    print('You are now running the demo for this module!')
    print('It will demonstrate the UbU prototcol by sending a sample file')
    print('Feel free to try something large and see how fast python really is')

    #globals
    global contacts
    global private_key
    global public_key
    contacts = [None]
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    server = Ulisten(('127.0.0.1', 9193), handler)

    with server:
        ip, port = server.server_address
        print('[L]Server will listen on:', ip, ':', port)

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print('[L]Server loop running in thread:', server_thread.name)

        print('-----------------------')
        print('Current Test Config:')
        print('File:', TEST_FILE)
        print('Remote Peer:', TEST_ADDRESS)
        print('Byte Order (Endian):', BYTE_ORDER)
        print()
        print('NOTE: You can change these options at the top of the script')
        print('-----------------------')

        input('Press Enter to send a file to the configured peer')

        demo()

def demo():
    peer = Usocket(TEST_ADDRESS, 1, private_key)
    contacts.append(peer)

if __name__ == '__main__':
    start()