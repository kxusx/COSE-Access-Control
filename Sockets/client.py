import socket
import json

c = socket.socket()
c.connect(('localhost',3000))

name = 'Drone-2'
c.send(bytes(name,'utf-8'))
print(c.recv(1024).decode())

Profile = {'name':'Drone1', 'id':1234}
# convert profile into json format
profile_json = json.dumps(Profile)
# send profile to server
c.send(bytes(profile_json,'utf-8'))
