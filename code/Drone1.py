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

mymsg="hello from Drone-1"

if (len(sys.argv)>1):
	mymsg=str(sys.argv[1])
 
drone1_private_key = urandom(32)

drone1= EC2Key(crv='P_256', d=drone1_private_key, optional_params={'KpAlg': 'EcdhEsHKDF256','KpKty': 'KtyEC2'})
drone1 = CoseKey.from_dict(drone1)

drone1pub = deepcopy(drone1)
del drone1pub[EC2KpD]

shared = DirectKeyAgreement(
    phdr = {Algorithm: EcdhEsHKDF256},
    uhdr = {EphemeralKey: drone1pub})

shared.key = drone1

IVal = urandom(16)

s = socket.socket()
print('Socket created') 

s.bind(('localhost',3000))
s.listen(3)
print('Waiting for connections')

while True:
    c, addr = s.accept()
    # name = c.recv(1024).decode()
    # print('Connected with ',addr,name)
    dr = {'drone1':drone1, 'drone1pub':drone1pub}
    dr_json = json.dumps(dr)
    c.send(bytes(dr,'utf-8'))
    # print(c.recv(1024).decode())
    c.close()