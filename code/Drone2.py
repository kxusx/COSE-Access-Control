import socket
from binascii import hexlify, unhexlify
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
import random
import time

mymsg="hello from Drone-1"

# public parameters
p=53
g=39

#secret number
b=random.randint(1,p)
print('b: ',b)

B = (g**b)%p
print('B: ',B)

if (len(sys.argv)>1):
	mymsg=str(sys.argv[1])

drone2_private_key = urandom(32)
drone2= EC2Key(crv='P_256', d=drone2_private_key, optional_params={'KpAlg': 'EcdhEsHKDF256','KpKty': 'KtyEC2'})

drone2 = CoseKey.from_dict(drone2)
drone2pub = deepcopy(drone2)
del drone2pub[EC2KpD]

c = socket.socket()
c.connect(('localhost',9999))

name = 'Drone-2'
profile = {'name':name, 'B':B}
profile_ser = json.dumps(profile)
c.send(bytes(profile_ser,'utf-8'))

dr1_key_material = c.recv(1024).decode()
dr1_key_material = json.loads(dr1_key_material)
drone1 = dr1_key_material['drone1']
drone1pub = dr1_key_material['drone1pub']
A = int(dr1_key_material['A'])

print('Connected to Drone1!!!')
print('Establishing the session key......')
time.sleep(2)

print('A: ',A)
session_key = (A**b)%p
print('Session key: ',session_key)

unhex = unhexlify(bytes(drone1,'utf-8'))
unhex_pub = unhexlify(bytes(drone1pub,'utf-8'))

drone1 = CoseKey.decode(unhex)
drone1pub = CoseKey.decode(unhex_pub)

serialized_key = drone2.encode()
sr_key = hexlify(serialized_key).decode()

serialized_key_pub = drone2pub.encode()
sr_keypub = hexlify(serialized_key_pub).decode()

key_material = {'drone2':sr_key, 'drone2pub':sr_keypub}
data_string = json.dumps(key_material) #data serialized

c.send(bytes(data_string,'utf-8'))


shared = DirectKeyAgreement(
    phdr = {Algorithm: EcdhEsHKDF256},
    uhdr = {EphemeralKey: drone1pub and drone2pub})

shared.key = drone1
shared.local_attrs = {StaticKey: drone2pub}

mymsg = input('Enter Message: ')    

IVal = urandom(16)

msg = EncMessage(
    phdr = {Algorithm: A128GCM},
    uhdr = {IV: IVal},
    payload = mymsg.encode(),
    recipients = [shared])

encoded = msg.encode()

encoded_hex = hexlify(encoded).decode()
c.send(bytes(encoded_hex,'utf-8'))  
print('Message Sent to Drone-1')

while True:
    print('Waiting for response........')
    print("Response message from Drone-1: ",c.recv(1024).decode())
    break
