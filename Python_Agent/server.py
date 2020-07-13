import configparser
import os
import datetime
import platform
import socket
import json
import pwd
import glob
import logging
import logging.config
import netifaces
from math import floor
from sys import exit
from sys import stdout
from pathlib import Path
import pkg_resources
import pyAesCrypt
import objcrypt
import rpi_helper
from os import stat,remove
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from AesCrypt import *
import requests
import base64

# import socket programming library 
import socket 

# import thread module 
from _thread import *
import threading 
from time import time,perf_counter,sleep

def check_ip(ip):
	url = "http://10.0.2.5:8000/checkip/"
	data ={'ipaddress': str(ip)}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	return r.text


print_lock = threading.Lock() 

flag = True
# thread function 

def threaded(c): 
	while True: 
	
		# data received from client 
		data = c.recv(1024) 
		msg = base64.b64decode(data)

		if not data: 
			print('Bye') 
			break
		
  
		with open("ca.key", "rb") as key_file:
			private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
		
		plaintext = private_key.decrypt(
			msg,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label = None
				)
			)		

		key = plaintext.decode('ascii')
		print ('Received key is: ',key) 
			
		c.send('key received'.encode('ascii'))

		attempt = c.recv(1024).decode('ascii')

		print(attempt)
		
		if(attempt!='resend'and attempt!='exit'):
			print('in')

			while True:
				data = c.recv(1024)

				if not data: 
					break
				print(data)
				a = AesCrypt()
				d = a.decrypt(key,data)
				print('Message received: ', d.decode('utf-8'))
				reply = str(input('Enter reply:'))
				b = a.encrypt(key,reply)
				c.send(b)
	
	# connection closed 
	c.close() 


def server(): 
	host = "" 

	# reverse a port on your computer 
	# in our case it is 12345 but it 
	# can be anything 
	port = 1234
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	s.bind((host, port)) 
	print("socket binded to port", port) 

	# put the socket into listening mode 
	s.listen(5) 
	print("socket is listening") 

	# a forever loop until client wants to exit 
	while True: 

		# establish connection with client 
		c, addr = s.accept() 

		# lock acquired by client 
		
		res = check_ip(addr[0])
		print(res)
		if(res != 'IPaddress registered'):
			break
		
		print('Connected to :', addr[0]) 
		
		# Start a new thread and return its identifier 
		start_new_thread(threaded, (c,)) 
	s.close() 

