import socket
import json

s = socket.socket()
print('Socket created') 

s.bind(('localhost',9999))
s.listen(3)
print('Waiting for connections')

while True:
    c, addr = s.accept()
    name = c.recv(1024).decode()
    print('Connected with ',addr,name)
    
    c.send(bytes('Connected to Drone-1','utf-8'))
    
    profile = c.recv(1024).decode()
    # convert profile from json to dictionary
    profile = json.loads(profile)
    print(profile["name"])

    c.close()
    
    
