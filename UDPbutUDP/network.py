#UDP server, contact sending, and everything else you need for truly connectionless data transfer

#python modules
import socket
import socketserver
import threading
import io
import numpy as np

#cryptography stuff
import nacl.utils
import nacl.secret
from nacl.hash import blake2b
from nacl.public import PrivateKey, PublicKey, Box

#encrypted packet format:
#
# 2 byte contact id 
# 4 byte unit index (nonce)
# - 502 byte encrypted chunk:
#       2 byte blake2b checksum
#       500 byte data
#

#new contact packet format
#
# 2 byte id == 0
# 4 byte unit index == i_max
# 2 byte reserved
# 32 byte public key
# 2 byte contact id
# 1 byte akn (0 for new, 1 for have)
#

#Takes bytestream and splits it up into units with 4 byte header index to be sent
class UDPStream:

    #init UDP socket and stream object
    def __init__(s, address, crypto, id):
        
        s.addr = address
        s.crypto = crypto
        s.id = id

        s.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.s_stream = io.BytesIO(b'') #send stream
        #s.r_stream = io.BytesIO(b'') #recv stream (NOT IMPLEMENTED YET)

    #send data to address
    def write(s, bytes):

        #write data to stream
        s.s_stream.seek(0)
        s.s_stream.truncate(0)
        s.s_stream.write(bytes)

        #send info packet
        s.send_info(s.s_stream.tell())

        s.s_stream.seek(0)
        index = 0

        # loop starter: read 504 bytes
        data = s.s_stream.read(504)

        #loop to send all data
        while data != b'':

            #create 4 byte header
            header = index.to_bytes(4, 'big', signed=False) #4 bytes (32 bit) in big endian #, signed=False

            #create unit
            unit = header + b' : ' + data
            #print(unit)

            #send unit
            s.sock.sendto(unit, s.addr)

            #increase order index and read next chunk
            data = s.s_stream.read(504)
            index += 1
       
    #send info packet
    def send_info(s, size):

        #init headers
        id = b'\x00\x00'

        #determine max index size
        i_size = math.floor(size / 504) #byte size divided by chunk size

        reserved = b'\x00\x00'

        #info packet
        data = b'send:' + i_size.to_bytes(4, 'big', signed=False) #, signed=False

        s.sock.sendto(data, s.addr)

#CUnit takes contact info and creates data
class CUnit:

    def __init__(s, contact, i_max, nonce_pre):

        s.contact = contact
        s.i_max = i_max
        s.nonce_pre = nonce_pre
        s.left = i_max

        #init data array
        s.data = [None] * i_max

    def add_unit(s, unit, index):

        #drop packet if index is already filled or index value is invalid
        try:
            if s.data[index] != None:
                return
        except:
            return

        #create nonce from nonce_prefix and index
        nonce = s.nonce_pre + index
        nonce = nonce.to_bytes(24, byteorder='big', signed=False)
        
        #decrypt data
        raw_data = s.contact.decrypt(unit, nonce)
        checksum = raw_data[0:2]
        data = raw_data[2:]

        #verify checksum
        person = s.conact.id.to_bytes(2, byteorder='big', signed=False)
        calc_checksum = blake2b(data, digest_size=2, person=person)

        #drop unit/packet if checksum doesn't match
        if checksum != calc_checksum:
            return

        #add to data
        try:
            s.data[index] = data
            s.left -= 1
        except:
            #invalid index, drop packet
            return

        #return True is cunit is complete
        if len(s.left) == 0:
            return True

    def read_data(s):
        data = b''
        for unit in s.data:
            data = data + unit

        return data

#Contact handler basically
class Contact:

    def __init__(s, pk, id, c_id, socket, i_max):

        s.nonce = 0
        s.id = id
        s.contact_id = c_id
        s.socket = socket
        s.cunit = CUnit(s, i_max, s.nonce)

        #init DH key
        box = Box(private_key, PublicKey(pk))
        DHsecret = box.shared_key()
        s.box = nacl.secret.SecretBox(DHsecret)

    #decrypt data with nonce
    def decrypt(s, data, nonce):
        return s.box.decrypt(data, nonce)

    #encrypt data to be sent
    def encrypt(s, data):
        nonce_raw = s.nonce.to_bytes(24, byteorder='big', signed=False)
        e_data = s.box.encrypt(data, s.nonce)
        s.nonce += 1
        return (nonce_raw, e_data)

#Server
class UDPHandler(socketserver.BaseRequestHandler):
    
    #handle data accordingly. Format is [data, socket] for udp
    def handle(self):

        raw_data = self.request[0]
        socket = self.request[1]

        #byte convert: int.from_bytes(b'', byteorder='big', signed=False)
        
        id = int.from_bytes(raw_data[0:2], byteorder='big', signed=False)
        u_index = int.from_bytes(raw_data[2:6], byteorder='big', signed=False)
        data = raw_data[6:]

        if id == 0:

            try:
                #new info unit 

                for c in contacts:
                    if c.id == id:
                        contact = c

                contact.cunit = CUnit(contact, u_index, contact.nonce)
                return
            except:

                #new info contact

                reserved = data[0:2]
                pk = data[2:34] #public key
                contact_id = int.from_bytes(data[34:36], byteorder='big', signed=False) #contact id
                akn = int.from_bytes(data[36:37], byteorder='big', signed=False) #contact aknowledgement

                try:
                    #create contact
                    id = len(contacts)
                    contact = Contact(pk, id, contact_id, socket, u_index)
                    contacts.append(contact)

                    #send return contact
                    if akn == 0:
                        #0 id + 0 index + 0 reserved + 32 key + 2 id + 1 akn
                        r_contact = b'\x00\x00\x00\x00\x00\x00\x00\x00' + public_key.__bytes__() + id.to_bytes(2, byteorder='big', signed=False) + b'\x01'
                        socket.sendto(r_contact, self.client_address)

                except:
                    print('contact packet was invalid!')
                    return
        else:
            try:
                #get contact
                contact = contacts[id]
                #print(contact.decrypt(data, u_index))
                complete = contact.cunit.add_unit(data, u_index)

                # if cunit is complete, read data and increment nonce_pre
                if complete:
                    print(contact.cunit.read_data())
                    contact.nonce = contact.nonce + 4294967296 #4 byte max value + 1
            except:
                print('contact id was invalid!')
                return

        #print(reserved)
        print(contacts)

#threaded mixin
class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):    
    pass

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
