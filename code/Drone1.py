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

## Public parameters
p=53
g=39

# Secret number
a=random.randint(1,p)
print('a: ',a)

A = (g**a)%p


drone1_private_key = urandom(32)

drone1= EC2Key(crv='P_256', d=drone1_private_key, optional_params={'KpAlg': 'EcdhEsHKDF256','KpKty': 'KtyEC2'})
drone1 = CoseKey.from_dict(drone1)

drone1pub = deepcopy(drone1)
del drone1pub[EC2KpD]

serialized_key = drone1.encode()
sr_key = hexlify(serialized_key).decode()

serialized_key_pub = drone1pub.encode()
sr_keypub = hexlify(serialized_key_pub).decode()

key_material = {'drone1':sr_key, 'drone1pub':sr_keypub, 'A':A}
data_string = json.dumps(key_material) #data serialized

s = socket.socket()
print('Socket created') 

s.bind(('localhost',9999))
s.listen(2)
print('Waiting for connections')

setupFlag = False

while True:
    c, addr = s.accept()
    
    profile_ser = c.recv(1024).decode()
    profile = json.loads(profile_ser)
    
    print('Connected with ',addr,profile['name'])
    print('Establishing the session key......')
    time.sleep(2) 
    
    B = int(profile['B'])
    
    Session_key = (B**a)%p
    print('Session key: ',Session_key)
        
    c.send(bytes(data_string,'utf-8'))
    dr2_key_material = c.recv(1024).decode()
    dr2_key_material = json.loads(dr2_key_material)
    drone2 = dr2_key_material['drone2']
    drone2pub = dr2_key_material['drone2pub']

    unhex = unhexlify(bytes(drone2,'utf-8'))
    unhex_pub = unhexlify(bytes(drone2pub,'utf-8'))

    drone2 = CoseKey.decode(unhex)
    drone2pub = CoseKey.decode(unhex_pub)
    setupFlag = True
    
    encoded_hex = c.recv(1024).decode()
    encoded = unhexlify(bytes(encoded_hex,'utf-8'))
    decoded = CoseMessage.decode(encoded)
    
    static_receiver_key = CoseKey.from_dict(drone1)
    decoded.recipients[0].key = drone1
    msg = decoded.decrypt(decoded.recipients[0]).decode()
    print ("\nMessage: ",msg)
    
    response = input(f'Enter response message to {profile["name"]}: ')
    c.send(bytes(response,'utf-8'))
    c.close()