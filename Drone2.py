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
import hashlib

Key_start_time = time.time()

PORT = 9998

json_object = None
with open('reg.json', 'r') as openfile:
    json_object = json.load(openfile)
    
## Public parameters
p=json_object['p']
g=json_object['g']

#secret number
b=random.randint(1,p)

# Sharing material to drone1 to establish session key
B = (g**b)%p

if (len(sys.argv)>1):
	mymsg=str(sys.argv[1])

## Drone2 private key
drone2_private_key = urandom(32)

## Drone2 content encrytption key
drone2= EC2Key(crv='P_256', d=drone2_private_key, optional_params={'KpAlg': 'EcdhEsHKDF256','KpKty': 'KtyEC2'})

drone2 = CoseKey.from_dict(drone2)

## Drone2 public key
drone2pub = deepcopy(drone2)

##Deleting private key instance from private key
del drone2pub[EC2KpD]

## Connection setup
c = socket.socket()
c.connect(('localhost',PORT))

name = 'Drone-2'
profile = {'name':name, 'B':B}
profile_ser = json.dumps(profile)

## Sending Drone2 profile to Drone1
c.send(bytes(profile_ser,'utf-8'))

dr1_key_material = c.recv(1024).decode()
dr1_key_material = json.loads(dr1_key_material)
drone1 = dr1_key_material['drone1']
drone1pub = dr1_key_material['drone1pub']
A = int(dr1_key_material['A'])

print('Connected to Drone1!!!')

## Establishing the session key
print('Establishing the session key......')
time.sleep(1)

print('A: ',A)
session_key = (A**b)%p

hashed_key = hashlib.sha256(str(session_key).encode('utf-8')).hexdigest()

json_object = None
with open('reg.json', 'r') as openfile:
    json_object = json.load(openfile)
    
if hashed_key != json_object['Session_key Hash']:
    print('Failed to establish session key!!!')
    c.send(bytes('failed!!','utf-8'))
    exit()
print('Session key: ',session_key)

c.send(bytes('Session Established!!!!','utf-8'))

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

## Used for authentication using EphemeralKey consist of drone1 and drone2 public key
shared = DirectKeyAgreement(
    phdr = {Algorithm: EcdhEsHKDF256},
    uhdr = {EphemeralKey: drone1pub and drone2pub})

shared.key = drone1
shared.local_attrs = {StaticKey: drone2pub}

Key_end_time = time.time()
print('Computation time in key establishment phase: ',Key_end_time-Key_start_time)


start = time.time()
curr = time.time()

while (curr-start) < 50:
    mymsg = input('Enter Message: ')
    curr = time.time()
    if (curr-start) > 50:
        break    

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
        encoded_hex = c.recv(1024).decode()
        if encoded_hex:
            print('Size of message received: ',len(encoded_hex),' bytes')
            encoded = unhexlify(bytes(encoded_hex,'utf-8'))
            decoded = CoseMessage.decode(encoded)

            static_receiver_key = CoseKey.from_dict(drone2)
            decoded.recipients[0].key = drone2
            msg = decoded.decrypt(decoded.recipients[0]).decode()
            print('Size of payload received: ',len(msg),' bytes')
            print ("\nResponse Message from Drone1: ",msg)
            print('\n')
            break
    
    curr = time.time()
    
if (curr-start) > 50:
    session_message = 'session over'
    IVal = urandom(16)

    msg = EncMessage(
        phdr = {Algorithm: A128GCM},
        uhdr = {IV: IVal},
        payload = session_message.encode(),
        recipients = [shared])

    encoded = msg.encode()

    encoded_hex = hexlify(encoded).decode()
    c.send(bytes(encoded_hex,'utf-8'))
    print('\nSession timed out!!!')
