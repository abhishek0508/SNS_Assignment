import socket, threading                   # Import socket module
import numpy as geek
import pyDH
from des import DesKey
import pickle

class Header:
   opcode = int()
   s_addr = str()
   d_addr = str()
   def __init__(self,opcode,s_addr,d_addr):
       self.opcode = opcode
       self.s_addr = s_addr
       self.d_addr = d_addr

class Message:
   hdr = None
   msg = None
   def __init__(self,hdr,msg):
       self.hdr = hdr
       self.msg = msg


d1 = pyDH.DiffieHellman()
d2 = pyDH.DiffieHellman()
d3 = pyDH.DiffieHellman()
pubkey_k1 = d1.gen_public_key()
pubkey_k2 = d2.gen_public_key()
pubKey_k3 = d3.gen_public_key()


s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print("Enter Port No.")
port = int(input())
s.connect((host, port))

slice_object = slice(0,8)

# Request for file
print("Enter filename")
filename = input()
hdr = Header(20,"127.0.0.1:6000","127.0.0.1:6000") 
message = Message(hdr,filename)
transfer_message = pickle.dumps(message)
s.send(transfer_message)

# Exhange Public_K1
print("PUBKEY")
hdr = Header(10,"127.0.0.1:6000","127.0.0.1:6000")
message = Message(hdr,pubkey_k1)
transfer_message = pickle.dumps(message)
s.send(transfer_message)
data = s.recv(1024)
msg_obj = pickle.loads(data)
pubkey_recv = msg_obj.msg
shared_key_k1 = d1.gen_shared_key(pubkey_recv)
shared_key_k1 = shared_key_k1[slice_object]


#Exchange Public_K2
print("PUBKEY")
message = Message(hdr,pubkey_k2)
transfer_message = pickle.dumps(message)
s.send(transfer_message)
data = s.recv(1024)
msg_obj = pickle.loads(data)
pubkey_recv = msg_obj.msg
shared_key_k2 = d2.gen_shared_key(pubkey_recv)
shared_key_k2 = shared_key_k2[slice_object]


#Exchange Public_K3
print("PUBKEY")
message = Message(hdr,pubKey_k3)
transfer_message = pickle.dumps(message)
s.send(transfer_message)
data = s.recv(1024)
msg_obj = pickle.loads(data)
pubkey_recv = msg_obj.msg
shared_key_k3 = d3.gen_shared_key(pubkey_recv)
shared_key_k3 = shared_key_k3[slice_object]

# final_key
final_key = shared_key_k1+shared_key_k2+shared_key_k3
# print(final_key)

received_filname = "recieved_"+filename
with open(received_filname, 'wb') as f:
    # print('file opened')
    while True:
        key0 = DesKey(bytes(final_key,"utf-8"))
        # print('receiving data...')
        buffer = s.recv(1024)
        # print('data=%s', (data))
        if not buffer:
            f.close()
            break
        data = key0.decrypt(buffer)
        f.write(data)
    print("DISCONNECT")

s.close()


