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

PORT = 9998

Key_start_time = time.time()

json_object = None
with open('reg.json', 'r') as openfile:
    json_object = json.load(openfile)
    
## Public parameters
p=json_object['p']
g=json_object['g']

# Secret number
a=random.randint(1,p)

# Sharing material to drone2 to establish session key
A = (g**a)%p

## Drone1 private key
drone1_private_key = urandom(32)

## Drone1 content encryption key
drone1= EC2Key(crv='P_256', d=drone1_private_key, optional_params={'KpAlg': 'EcdhEsHKDF256','KpKty': 'KtyEC2'})
drone1 = CoseKey.from_dict(drone1)

## Drone1 public key
drone1pub = deepcopy(drone1)
del drone1pub[EC2KpD]

serialized_key = drone1.encode()
sr_key = hexlify(serialized_key).decode()

serialized_key_pub = drone1pub.encode()
sr_keypub = hexlify(serialized_key_pub).decode()



### Socket connection establishment
s = socket.socket()
print('Socket created') 

s.bind(('localhost',PORT))
s.listen(1)
print('Waiting for connections')

c, addr = s.accept()

profile_ser = c.recv(1024).decode()
profile = json.loads(profile_ser)

print('\nConnected with ',addr,profile['name'])
print('\nEstablishing the session key......')
time.sleep(1) 

B = int(profile['B'])

Session_key = (B**a)%p

Hashed_session_key = hashlib.sha256(str(Session_key).encode('utf-8')).hexdigest()
print('Session key: ',Hashed_session_key)

json_object['Session_key Hash'] = Hashed_session_key

json_update = json.dumps(json_object, indent=4)

with open("reg.json", "w") as outfile:
    outfile.write(json_update)
    
    
key_material = {'drone1':sr_key, 'drone1pub':sr_keypub, 'A':A}
data_string = json.dumps(key_material) #data serialized
    
c.send(bytes(data_string,'utf-8'))

session_msg = c.recv(1024).decode()

if session_msg == 'failed!!':
    print('Failed to establish session key!!!')
    exit()
else:
    print(session_msg)

dr2_key_material = c.recv(1024).decode()
dr2_key_material = json.loads(dr2_key_material)
drone2 = dr2_key_material['drone2']
drone2pub = dr2_key_material['drone2pub']

unhex = unhexlify(bytes(drone2,'utf-8'))
unhex_pub = unhexlify(bytes(drone2pub,'utf-8'))

drone2 = CoseKey.decode(unhex)
drone2pub = CoseKey.decode(unhex_pub)

## Used for authentication using EphemeralKey consist of drone1 and drone2 public key
shared = DirectKeyAgreement(
    phdr = {Algorithm: EcdhEsHKDF256},
    uhdr = {EphemeralKey: drone2pub and drone1pub})

shared.key = drone2
shared.local_attrs = {StaticKey: drone1pub}

Key_end_time = time.time()
print('Computation time in key establishment phase: ',Key_end_time-Key_start_time)

while True:
    encoded_hex = c.recv(1024).decode()
    if encoded_hex:
        print('Size of message received: ',len(encoded_hex),' bytes')
        start = time.time()
        encoded = unhexlify(bytes(encoded_hex,'utf-8'))
        decoded = CoseMessage.decode(encoded)

        static_receiver_key = CoseKey.from_dict(drone1)
        decoded.recipients[0].key = drone1
        msg = decoded.decrypt(decoded.recipients[0]).decode()
        print('Size of payload received: ',len(msg),' bytes')
        
        if msg == 'session over':
            print('Session Timed out!!!')
            break
        print ("\nMessage: ",msg)
        endTime = time.time()
        print('Computation time for each message: ',endTime-start)
        response = input(f'Enter response message to {profile["name"]}: ')
        IVal = urandom(16)

        msg = EncMessage(
        phdr = {Algorithm: A128GCM},
        uhdr = {IV: IVal},
        payload = response.encode(),
        recipients = [shared])

        encoded = msg.encode()

        encoded_hex = hexlify(encoded).decode()
        c.send(bytes(encoded_hex,'utf-8'))  

c.close()