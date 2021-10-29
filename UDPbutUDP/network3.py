#UDP server, contact sending, and everything else you need for truly connectionless data transfer

#python modules
import math
import socket
import socketserver
import threading
import io
import numpy as np
import nacl.utils
import nacl.secret
from nacl.hash import blake2b
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey

#packet formats:

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
#   1 byte send return (0 for need, 1 for have)
#

#new data send packet format
#
# 2 byte id == 0
# 2 byte id ==  > 0
# 504 byte encrypted chunk:
#   2 byte blake2b checksum
#   1 byte type 
#   20 byte nonce prefix
#

#data miss request
#
# 2 byte id == 0
# 2 byte id == > 0
# 504 bytes encrypted chunk:
#   2 byte blacke2b checksum
#   1 byte type
#   20 byte nonce prefix
#   - 4 byte index chunks
#

#Data constructer and encryption
class CUnit:
    
    #init 
    def __init__(s, keypair, nonce_pre, id, size=0):
        
        s.sign_key = SigningKey(keypair[0])
        temp_box = Box(keypair[0], keypair[1])
        s.box = nacl.secret.SecretBox(temp_box.shared_key()) #Derive a DH Shared secret box
        s.nonce_pre = nonce_pre
        s.id = id

        #writeable stream for picky modules that only use .write()
        s.stream = io.BytesIO(b'')

        s.map = [None] * size #used to send and build data from UDP

    #Construction

    #special method for writing with streams, otherwise use write_data()
    def write(s, bytes):

        #write data to stream
        s.stream.write(bytes)

        s.stream.seek(0)
        index = 0

        #loop starter: read 500 bytes
        data = s.s_stream.read(500)

        #loop to send all data
        while data != b'':

            #encrypt chunk
            data = encrypt(data, len(s.map) - 1)
            
            #append to map
            s.map.append(data)

            data = s.s_stream.read(500)
            index += 1

        #clear stream
        s.stream.seek(0)
        s.stream.truncate(0)
    
    #writes data to map
    def write_data(s, data):

        max = math.ceil(len(data) / 500)
        index = 1 # this offset disgusts me lol

        while index <= max:

            #read 500 byte chunk
            chunk = index * 500
            base = chunk - 500

            unit = data[base:chunk]

            unit = encrypt(unit, len(s.map) - 1)

            s.map.append(unit)

            index += 1

    #Reconstruction

    #Adds encrypted unit to map
    def add_unit(s, unit, index):
        
        cleaned_unit = decrypt(unit, index)

        if cleaned_unit:

            try:
                s.map[index] = unit
                return not (None in s.map) #returns True if map is complete
            except:
                return False

        return False

    #Encryption

    #encrypts unit
    def encrypt(s, data, index):

        #calculate nonce
        nonce = s.nonce_pre + index.to_bytes(4, byteorder='big', signed=False)

        #calculate checksum
        person = s.id.to_bytes(2, byteorder='big', signed=False)
        checksum = blake2b(data, digest_size=2, person=person)

        #append checksum
        data = checksum + data

        #encrypt and return
        cipher = s.box.encrypt(data, nonce)
        return cipher

    #decrypts unit
    def decrypt(s, data, index):
        
        #calculate nonce
        nonce = s.nonce_pre + index.to_bytes(4, byteorder='big', signed=False)

        #decrypt
        decrypt = s.box.decrypt(data, nonce)
        checksum = decrypt[0:2]
        plaintext = decrypt[2:]

        #calculate checksum
        person = s.id.to_bytes(2, byteorder='big', signed=False)
        calc_checksum = blake2b(plaintext, digest_size=2, person=person)

        if checksum != calc_checksum:
            print('checksum invalid!')
            return None

        return plaintext

    #signs unit
    def sign(s, data):
        
        return s.sign_key.sign(data)

    #verifies unit
    def verify(s, data, key):
        
        verify_key = VerifyKey(key)

        try:
            verify_key.verify(data.messgae, data.signature)
            return True
        except:
            return False

#UDP Contact class
class Contact:
    
    def __init__(s, socket, address, local_id, remote_id, pk):

        s.socket = socket
        s.address = address
        s.local_id = local_id
        s.remote_id = remote_id
        s.keypair = (private_key, pk)
        s.units = []

    #send data
    def send_data(s, cunit):
        
        #send new data packet
        s.__send_new_data(cunit)

        #send peices
        id = s.remote_id.to_bytes(2, byteorder='big', signed=False)
        index = 0
        map = cunit.map

        while index < len(map):

            data = map[index]
            index_raw = index.to_bytes(4, byteorder='big', signed=False)

            #add header
            unit = id + index + data

            #send unit
            s.socket.sendto(data, s.address)

            index += 1

    #send peice
    def send_data_peice(s, data, index):
        
        #send peice
        id = s.remote_id.to_bytes(2, byteorder='big', signed=False)
        #add header
        unit = id + index + data

        #send unit
        s.socket.sendto(data, s.address)

    #send new data packet
    def send_new_data(s, cunit):

        id = b'\x00\x00' #special 0 id
        real_id = s.remote_id.to_bytes(4, byteorder='big', signed=False) #actual id since special id is in use
        header = id + real_id

        nonce_pre = cunit.nonce_pre #nonce pre

        #encrypt header with nonce for validation
        cipher = s.box.encrypt(data, nonce_pre)
        data = data + cipher

        #send packet
        s.socket.sendto(data, s.address)

    #send new contact packet
    def send_new_contact(s, have):

        id = b'\x00\x00' #special 0 id
        real_id = b'\x00\x00' #special 0 real id
        sign_key = SigningKey(private_key)
        key =  sign_key.verify_key.__bytes__() #public key in bytes

        remote_id = s.local_id.to_bytes(2, byteorder='big', signed=False) #local contact id

        #request for contact info if it doesn't exist
        if have:
            send_return = b'\x01'
        else:
            send_return = b'\x00'

        #sign remote_id + send return
        unsigned = remote_id + send_return
        signed = sign_key.sign(unsigned)

        #construct packet
        data = id + real_id + key + signed

        #send packet
        s.socket.sendto(data, s.address)

    #send missing data packets
    def send_miss_request(s, missed):
        #send packets requesting resend of missing packets
        
        id = b'\x00\x00' #special 0 id
        index = b'\x00\x00\x00\x00' #0 index
        type = b'\x00\x02' #special type 2
        nonce = s.nonce_pre.to_bytes(24, byteorder='big', signed=False)

        data = id + index + type + nonce

        for ind in missed:
            index = ind.to_bytes(4, byteorder='big', signed=False)
            data = data + index

        s.socket.sendto(data, s.address)

#Threaded mixin for UDPServer
class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):    
    pass

#UDPHandler which handles each packet as a new thread. Each handle call is also inside a try-except
class UDPHandler(socketserver.BaseRequestHandler):
    
    #handle data accordingly. Format is [data, socket] for udp
    def handle(self):

        unit = self.request[0]
        socket = self.request[1]

        #decontruct contact id header
        id = int.from_bytes(unit[0:2], byteorder='big', signed=False)
        
        #special id = o packet handling
        if id == 0:
            real_id = int.from_bytes(unit[2:4], byteorder='big', signed=False)

            #new contact packet
            if real_id == 0:
                
                key = unit[4:38]
                signed = unit[38:]

                #verify signature
                v_key = VerifyKey(key)

                try:
                    c_data = v_key.verify(signed)
                    remote_id = c_data[0:2]
                    send_return = c_data[2:3]

                except:
                    print('New contact verifictaion failed')
                    return

                #create new id

                new_id = len(contacts)
                contact = Contact(socket, self.client_address, new_id, remote_id, (private_key, key))
                contacts.append(contact)

            else:
                pass

        #regular data packet
        else:
            index = int.from_bytes(unit[2:6], byteorder='big', signed=False)

 

#Starts UDPServer
def start():

    #globals
    global private_key
    private_key =  PrivateKey.generate()
    global public_key
    public_key = private_key.public_key
    global contacts
    contacts = [None]
    
    server = ThreadedUDPServer(('127.0.0.1', 9193), UDPHandler)

    with server:
        ip, port = server.server_address
        print(ip, port)

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)

        #press enter to exit
        input()

        server.shutdown()

if __name__ == '__main__':
    start()