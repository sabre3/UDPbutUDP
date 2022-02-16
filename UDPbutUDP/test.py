#Another reimplmentation yet again

from ctypes import sizeof
from nacl.exceptions import BadSignatureError
import nacl.utils
import nacl.secret
from nacl.hash import blake2b
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey

import io

#byteorder
BO = 'big'
#Maximum Transmission Unit size in bytes. Also same as data "piece" size 
MTU = 512 

class Contact:

    def __init__(s, id, remote_id, private_key, public_key, nonce_pre, socket):

        s.id = id
        s.remote_id = remote_id
        s.nonce_pre = nonce_pre
        s.socket = socket

        temp_box = Box(private_key, public_key)
        s.box = nacl.secret.SecretBox(temp_box.shared_key()) #Derive a DH Shared secret box

        s.stream = io.BytesIO(b'')

    #write binary to stream at index
    def write(s, bin, index):
        s.stream.seek(MTU * index)
        s.write(bin)

    #decrypt piece
    def decrypt(s, bin, index_raw):
        nonce = s.nonce_pre + index_raw
        open = s.box.decrypt(bin, nonce)

        checksum = open[0:2]
        payload = open[2:]

        #verify checksum
        check = blake2b(payload, digest_size=2,salt=index_raw)

        if check == checksum:
            return payload
        
        return None

    #decrypt miss data request
    def decrypt_miss(s, bin):
        nonce = s.nonce_pre
        open = s.box.decrypt(bin, nonce)
        #!@#$

    #decrypt end contact checksum
    def decrypt_del(s, bin):
        nonce = s.nonce_pre
        open = s.box.decrypt(bin, nonce)

        checksum = open[0:2]
        payload = s.id

        #verify checksum
        check = blake2b(payload, digest_size=2) #do we really need a salt?

        if check == checksum:
            return payload
        
        return None

class Upacket:

    contacts = []
    private_key = PrivateKey.generate()

    def __init__(s, bin):
        id = bin[0:2]
        s.id = int.from_bytes(id, byteorder=BO, signed=False)

    def get_contact(id):
        for c in Upacket.contacts:
            if id == c.id:
                return c

    def add_contact(contact):
        for c in Upacket.contacts:
           if c is None:
                id = Upacket.contacts.index(c)

        contact.id = id
        Upacket.contacts.append(contact)

    def remove_contact(id):
        for c in Upacket.contacts:
            if id == c.id:
                i = Upacket.contacts.index(c)
                Upacket.contacts.insert(None, i)
                Upacket.contacts.remove(c)


class UNpacket(Upacket):

    def __init__(s, bin):

        index = bin[2:6]
        encrypted = bin[6:]

        s.index = int.int.from_bytes(index, byteorder=BO, signed=False)

        contact = Upacket.get_contact(id)
        payload = contact.decrypt(encrypted, index)
        if payload is None:
            return False
        contact.write(payload, index)

        return True

class USpacket(Upacket):

    def __init__(s, bin, socket):
        
        s.type = int.int.from_bytes(bin[2:3], byteorder=BO, signed=False)

        if s.type == 0:
            
            public_key = bin[3:35]
            signed = bin[35:]
            
            vk = VerifyKey(public_key)
            try:
                data = vk.verify(signed)
            except BadSignatureError:
                return False

            nonce_pre = data[0:20]
            remote_id = int.from_bytes(data[20:22], byteorder=BO, signed=False)
            need_id = int.from_bytes(data[22:23], byteorder=BO, signed=False)

            contact = Contact(0, remote_id, Upacket.private_key, public_key, nonce_pre, socket)
            Upacket.add_contact(contact)

        elif s.type == 1:
            pass
        elif s.type == 2:
            
            id = int.from_bytes(bin[3:5], byteorder=BO, signed=False)
            encrypted = bin[5:7]
            contact = Upacket.get_contact(id)
            payload = contact.decrypt_del(encrypted)
            if payload is None:
                return False

            Upacket.remove_contact(id)

            return True

        else:
            return False

