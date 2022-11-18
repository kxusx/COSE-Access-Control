import socket

c = socket.socket()
c.connect(('localhost',3000))

name = 'Drone-2'
c.send(bytes(name,'utf-8'))
print(c.recv(1024).decode())

Profile = {'name':'Drone1', 'id':1234}
c.send(bytes('Hey, Drone-1','utf-8'))