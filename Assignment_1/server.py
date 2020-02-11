import socket, threading                  # Import socket module
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
   msg = str()
   def __init__(self,hdr,msg):
      self.hdr = hdr
      self.msg = msg


class ClientThread(threading.Thread):
   clientAddr = None
   csocket = None
   def __init__(self,clientSocket,clientAddr):
      threading.Thread.__init__(self)
      self.csocket = clientSocket
      self.clientAddr = clientAddr
      print("New Connection added")
   def run(self):
      print("Connection from:",self.clientAddr)

      d1 = pyDH.DiffieHellman()
      d2 = pyDH.DiffieHellman()
      d3 = pyDH.DiffieHellman()

      slice_object = slice(8)

      pubkey_k1 = d1.gen_public_key()
      pubkey_k2 = d2.gen_public_key()
      pubkey_k3 = d3.gen_public_key()

      # File Name accept request
      buffer = self.csocket.recv(1024)
      msg_obj = pickle.loads(buffer)
      opcode = msg_obj.hdr.opcode
      if(opcode == 20):
         print("REQSERV")
         filename = msg_obj.msg
      # print(filename)

      try:
         f = open(filename,'rb')
      except:
         print("No Such File Exists")
         print("DISCONNECT")
         self.csocket.close()
         return

      # Receive & Send Public Key K1   
      hdr = Header(10,"127.0.0.1:6000","127.0.0.1:6000")

      print("PUBKEY")
      data = self.csocket.recv(1024)
      msg_obj = pickle.loads(data)
      pubkey_recv = int(msg_obj.msg) 
      shared_key_k1 = d1.gen_shared_key(pubkey_recv)
      shared_key_k1 = shared_key_k1[slice_object]
      message = Message(hdr,pubkey_k1)
      transfer_message = pickle.dumps(message)
      self.csocket.send(transfer_message)

      # Receive & Send Public Key K2
      print("PUBKEY")
      data = self.csocket.recv(1024)
      msg_obj = pickle.loads(data)
      pubkey_recv = int(msg_obj.msg) 
      shared_key_k2 = d2.gen_shared_key(pubkey_recv)
      shared_key_k2 = shared_key_k2[slice_object]
      message = Message(hdr,pubkey_k2)
      transfer_message = pickle.dumps(message)
      self.csocket.send(transfer_message)

      # Receive & Send Public Key K3
      print("PUBKEY")
      data = self.csocket.recv(1024)
      msg_obj = pickle.loads(data)
      pubkey_recv = int(msg_obj.msg) 
      shared_key_k3 = d3.gen_shared_key(pubkey_recv)
      shared_key_k3 = shared_key_k3[slice_object]
      message = Message(hdr,pubkey_k3)
      transfer_message = pickle.dumps(message)
      self.csocket.send(transfer_message)

      final_key = shared_key_k1+shared_key_k2+shared_key_k3
      # print(final_key)
   
      l = f.read(64)
      while (l):
         key0 = DesKey(bytes(final_key,"utf-8"))
         print("ENCMSG")
         if(len(l)%8!=0):
            encrypted_block = key0.encrypt(l,padding=True)
         else:
            encrypted_block = key0.encrypt(l)
         self.csocket.send(encrypted_block)
         l = f.read(64)
      print("REQCOMP")
      f.close()
      self.csocket.close()


print("Enter port")
port = int(input())                # Reserve a port for your service.
s = socket.socket()                # Create a socket object
host = socket.gethostname()        # Get local machine name
s.bind((host, port))               # Bind to the port


threads = []
while True:
   s.listen(5)
   print('Server listening....')
   conn, addr = s.accept()
   newthread = ClientThread(conn,addr)
   newthread.start()
   threads.append(newthread)
   
for t in threads:
   t.join()
