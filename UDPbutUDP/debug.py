#debug stuff

#cryptography stuff
import nacl.utils
import nacl.secret
import nacl.encoding
import numpy as np
import socket
from nacl.hash import blake2b
from nacl.public import PrivateKey, Box



#debug


str = 'Hello yes I am a human lol'
print(str[:2])
print(str[:50].strip())

exit()

sk = PrivateKey.generate()
pk = sk.public_key

print(sk)
print(pk)

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

data = b'\x00\x00\x00\x00\x00\x00\x00\x00' + pk.__bytes__() + b'\x00\x01' + b'\x00'

socket.sendto(data, ('127.0.0.1', 9193))

print(socket.recv(1024))



exit()

a = np.empty(10, dtype=np.uintc)

for b in a:
    if b == None:
        print('lol')
    #print(b)

exit()

data = b'lmao my cool block data'
hash = blake2b(data, digest_size=2, encoder=nacl.encoding.RawEncoder)

print(hash)

exit()

sk = PrivateKey.generate()
pk = sk.public_key

print(pk.SIZE)

box1 = Box(sk, pk)
key = box1.shared_key()

box2 = nacl.secret.SecretBox(key)

nonce = 15
nonce = nonce.to_bytes(24, byteorder='big', signed=False)

lol = box2.encrypt(b'lmaoo', nonce)

print(lol)

exit()
