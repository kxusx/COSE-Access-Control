import socket
from binascii import hexlify
from copy import deepcopy
from os import urandom
from pycose.messages import EncMessage,CoseMessage
from pycose.keys import CoseKey
from pycose.messages.recipient import DirectKeyAgreement
from pycose.headers import Algorithm, StaticKey, EphemeralKey, IV
from pycose.algorithms import EcdhEsHKDF256, A128GCM
from pycose.keys.keyparam import EC2KpD
from pycose.keys import EC2Key
import sys
import json

drone2_private_key = urandom(32)
drone2= EC2Key(crv='P_256', d=drone2_private_key, optional_params={'KpAlg': 'EcdhEsHKDF256','KpKty': 'KtyEC2'})

drone2 = CoseKey.from_dict(drone2)
drone2pub = deepcopy(drone2)
del drone2pub[EC2KpD]


c = socket.socket()
c.connect(('localhost',3000))

dr = ''
while True:
    dr=c.recv(1024).decode()
    dr = json.loads(dr)
    print(dr)
    break

# print(dr)

# shared = DirectKeyAgreement(
#     phdr = {Algorithm: EcdhEsHKDF256},
#     uhdr = {EphemeralKey: alicepub and drone2pub})

# shared.key = drone1
# shared.local_attrs = {StaticKey: drone2pub}

# name = 'Drone-2'
# c.send(bytes(name,'utf-8'))
# print(c.recv(1024).decode())

# c.send(bytes('Hey, Drone-1','utf-8'))