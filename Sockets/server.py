import socket

s = socket.socket()
print('Socket created') 

s.bind(('localhost',3000))
s.listen(3)
print('Waiting for connections')

while True:
    c, addr = s.accept()
    name = c.recv(1024).decode()
    print('Connected with ',addr,name)
    
    c.send(bytes('Connected to Drone-1','utf-8'))
    # profile = c.recv(1024).decode()
    print(c.recv(1024).decode())
    c.close()
    
    