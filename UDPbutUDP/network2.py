#UDP server, contact sending, and everything else you need for truly connectionless data transfer

#python modules
import socket
import socketserver
import threading
import io
import numpy as np
import nacl.utils
import nacl.secret
from nacl.hash import blake2b
from nacl.secret import SecretBox
from nacl.public import PrivateKey, PublicKey, Box

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
# 2 byte id == 0
# 4 byte unit index
# 2 byte type
# 500 byte data
#

#new contact packet format
#
# 2 byte id == 0
# 4 byte unit index == 0
# 2 byte type == 0
# 32 byte public key
# 2 byte remote id
# 1 byte send return (0 for need, 1 for have)

#new data send packet format
#
# 2 byte id == 0
# 4 byte unit index == map_length
# 2 byte type == 1
# 2 byte id = contact id
# 24 byte nonce pre
# signed header
#

#data miss request
#
# 2 byte id = 0
# 4 byte unit index == 0
# 2 byte type == 2
# 24 byte nonce pre
#  - 4 byte index chunks
#

#Dev Notes:

# 4 bytes = 32 bits
#
# Max safe UDP packet size is 508 bytes to meet the 60 byte ip header + 8 byte UDP header = 576 bytes (minimum MTU)
# Using an unsigned 4 byte header, we can represent about 2 billion 500 byte data chunks
# Therefore, you can send about a 2TB file using an additional 4 byte UDP header for gauranteed delivery
#
# Since we want a way to handle packets from multiple sources on the same channel/port, we can use 2 bytes
# to assign contact IDs to sending and receving messages (65k possible contacts)
# 
# Obviously we don't want anyone easily impersonating someone so we use an asymmetric DH key derived
# from the contact public key and local private key. Since encryption by itself doesn't have any
# validation, we can use the remaining 2 bytes as a blake2b checksum to ensure the data is
# correctly decrypted
#
# This system has a waste of about 1 byte per packet since realistically,
# no one will be sending 2TB files over the internet lol (but I mean who knows?)
#
# Also for future, system should be improved to determine maximum MTU
# automatically to maximize packet size (ipv6 is generally 1500 byte mtu)
#
# All in all the system only uses an additional 8 bytes, leaving exactly 500 bytes of data per packet which
# is I think 2 bytes more than QUIC and a huge 12 bytes less than regular TCP
#
# The most important fetaure however is that this isn't a UDP stream. As of now, everything is
# sent as is (encrypted obviously) as individual datagram messages. This has the huge advantage of
# not having to handle the overhead of a stream but currently has the drawback of having to run
# a UDP receiver server which requires potential port forwarding (UDP Hole Punching planned maybe)
#
# Another experimental feature to try out with this system later is sending occasional redundant packets
# as a way to counter packet loss rather than having to renegotiate lost packets
#
#

#some TODO: add a check to make sure nonce_pre is greater than currently set nonce_pre before updating

#Contact class which is created from a contact packet and holds info
class Contact:
    
    def __init__(s, socket, address, local_id, remote_id, pk):

        s.socket = socket
        s.address = address
        s.local_id = local_id
        s.remote_id = remote_id
        s.pk = pk
        s.nonce_pre = 0
        
        #init DH key
        box = Box(sk, PublicKey(pk))
        DHsecret = box.shared_key()
        s.box = nacl.secret.SecretBox(DHsecret)

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

    #send new data packet
    def __send_new_data(s, cunit):

        id = b'\x00\x00' #special 0 id
        index = len(cunit.map).to_bytes(4, byteorder='big', signed=False) #map length
        type = b'\x00\x01' #special packet type 1 (new send)
        contact_id = s.remote_id.to_bytes(4, byteorder='big', signed=False) #actual id since special id is in use
        nonce_pre = s.nonce_pre.to_bytes(24, byteorder='big', signed=False) #nonce pre

        data = id + index + type + contact_id + nonce_pre

        #encrypt header with nonce for validation
        cipher = s.box.encrypt(data, nonce_pre)
        data = data + cipher

        #send packet
        s.socket.sendto(data, s.address)

    #send new contact packet
    def __send_new_contact(s, have):

        id = b'\x00\x00' #special 0 id
        index = b'\x00\x00\x00\x00' #0 index
        type = b'\x00\x00' #special type 0
        key =  s.pk.__bytes__() #public key
        remote_id = s.local_id.to_bytes(2, byteorder='big', signed=False) #local contact id

        #request for contact info if it doesn't exist
        if have:
            send_return = b'\x01'
        else:
            send_return = b'\x00'

        #construct packet
        data = id + index + type + key + remote_id + send_return

        #send packet
        s.socket.sendto(data, s.address)

    #send missing data packets
    def __send_miss_request(s, missed):
        #TODO
        #send packets requesting resend of missing packets
        pass

#Base CUnit class
class CUnit:

    def __init__(s, box, nonce_pre, id):
        
        s.box = box
        s.nonce_pre = nonce_pre
        s.id = id

    #encrypts unit
    def encrypt(s, data, index):

        #calculate nonce
        nonce = s.nonce_pre + index
        nonce = nonce.to_bytes(24, byteorder='big', signed=False)

        #calculate checksum
        person = s.id.to_bytes(2, byteorder='big', signed=False)
        checksum = blake2b(data, digest_size=2, person=person)

        #append checksum
        data = checksum + data

        #encrypt and return
        cipher = s.box.encrypt(data, s.nonce)
        return cipher

    #decrypts unit
    def decrypt(s, data, index):
        
        #calculate nonce
        nonce = s.nonce_pre + index
        nonce = nonce.to_bytes(24, byteorder='big', signed=False)

        #decrypt
        decrypt = s.box.decrypt(data, s.nonce)
        checksum = decrypt[0:2]
        plaintext = decrypt[2:]

        #calculate checksum
        person = s.id.to_bytes(2, byteorder='big', signed=False)
        calc_checksum = blake2b(plaintext, digest_size=2, person=person)

        if checksum != calc_checksum:
            print('checksum invalid!')
            return None

        return plaintext

#CUnit class which handles unit contruction and encryption
class CCUnit(CUnit):

    def __init__(s, box, nonce_pre, id):

        super().__init__(box, nonce_pre, id)

        s.map = []

        #writeable stream for picky modules that only use .write()
        s.stream = io.BytesIO(b'')

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
            
            s.map.append(data)

            data = s.s_stream.read(500)
            index += 1

        #clear stream
        s.stream.seek(0)
        s.stream.truncate(0)
    
    #writes data to map
    def write_data(s, data):

        max = len(data)
        index = 1 # this offset disgusts me lol

        while index < max:

            #read 500 byte chunk
            chunk = index * 500
            base = chunk - 500

            unit = data[base:chunk]
            s.map.append(unit)

            index += 1

    #encrypts map data
    def encrypt_map(s):

        index = 0

        #fun fact: while loops are faster in Python because there's no type checking involved for each iteration
        while index < len(s.map):

            data = s.map[index]

            #calculate nonce
            nonce = s.nonce_pre + index
            nonce = nonce.to_bytes(24, byteorder='big', signed=False)

            #calculate checksum
            person = s.id.to_bytes(2, byteorder='big', signed=False)
            checksum = blake2b(data, digest_size=2, person=person)

            #append checksum
            data = checksum + data

            #encrypt and update map
            cipher = s.box.encrypt(data, s.nonce)
            s.map[index] = cipher

            index += 1        

    #decrypts map data
    def decrypt_map(s):

        index = 0

        while index < len(s.map):

            data = s.map[index]

            #calculate nonce
            nonce = s.nonce_pre + index
            nonce = nonce.to_bytes(24, byteorder='big', signed=False)

            #decrypt
            decrypt = s.box.decrypt(data, s.nonce)
            checksum = decrypt[0:2]
            plaintext = decrypt[2:]

            #calculate checksum
            person = s.id.to_bytes(2, byteorder='big', signed=False)
            calc_checksum = blake2b(plaintext, digest_size=2, person=person)

            #verify checksum
            if checksum != calc_checksum:
                print('checksum invalid!')
                #consider throwing an exception instead
                break

            s.map[index] = cipher

            index += 1

#Cunit class which handles unit deconstruction and decryption
class DCUnit(CUnit):
    
    def __init__(s, box, nonce_pre, id, size):

        super().__init__(box, nonce_pre, id)

        s.map = [None] * size

    #add unit to data, handle appropriate checks as well
    def add_unit(s, unit):

        #get info stuff
        local_id = int.from_bytes(unit[0:2], byteorder='big', signed=False)
        index = int.from_bytes(unit[2:6], byteorder='big', signed=False)
        data = unit[6:]

        #drop packet if id doesn't match
        if local_id != s.id:
            return

        #drop packet if index is already filled or index value is invalid
        try:
            if s.map[index] == None:
                return
        except:
            return
        
        #decrypt data (checksum is verified by method)
        plaintext = s.decrypt(data, index)

        #drop pakcet if decrypt fails
        if plaintext == None:
            return 

        #add to map
        s.map[index] = data

        #if map is complete return true
        if None in s.map:
            return False

        return True

    #returns list of indexes with misisng data
    def get_missing(s):

        index = 0
        missing = []

        while index < len(s.map):

            if s.map[index] == None:
                missing.append(index)

            index += 1

        return missing

    #returns completed unit data
    def read(s):

        data = b''

        for unit in s.map:
            data = data + unit

        return data
