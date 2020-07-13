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
import base64
from os import stat,remove
from AesCrypt import *
import random
import string
from time import time, perf_counter,process_time,get_clock_info,sleep
from __init__ import get_primary_ip

from rpi_helper import Confinement, detect_confinement, detect_installation, get_deb_packages

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import rsa
from timeit import default_timer as timer
	
def verify(host):
	try:
		with open(host + '_ca.crt','rb') as f:
			cert = x509.load_pem_x509_certificate(f.read(), default_backend())
		public_key = cert.public_key()
		public_key.verify(
			cert.signature,
			cert.tbs_certificate_bytes,
			# Depends on the algorithm used to create the certificate
			padding.PKCS1v15(),
			cert.signature_hash_algorithm,
		)
		return'signature verified'
	except InvalidSignature:
		return 'verification unsuccessful'

def client(): 
	# local host IP '127.0.0.1' 

	availability = True
	no_rtattempt = True
	ca_certificate = True
	no_retransmission = True
	no_delay          = True
	
	
	delay_val = 0 
		

	host = str(input("Enter IP address of the device to communicate with: "))
	
	urlp = "http://10.0.2.5:8000/getvals/"
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

	# Define the port on which you want to connect 
	port = 1234

	try:
		
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 

	# connect to server on local computer 
		s.connect((host,port))
		
	
	except OSError:
		print ('Device unavailable')
		availability = False
		no_retransmission = False
		no_delay          = False
		delay_val = 100 
		
	

	url = "http://10.0.2.5:8000/sendca/"
	data ={'ipaddress': host}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	if(not str(r.text) == 'FileNotFound'):
		with open(host +'_ca.crt', 'w') as f:
    			f.write(r.text)
	else:
		print ('Certificate does not exist for secure communication')
		ca_certificate = False
		no_retransmission = False
		no_delay          = False
		delay_val = 100
		
		
	
	
	if(availability and ca_certificate):

		check = verify(host)
		print(check)
		if(check != 'signature verified'):
			print('Integrity check failed')
			s.close()
		with open(host +'_ca.crt','rb') as f:
			cert = x509.load_pem_x509_certificate(f.read(), default_backend())
	

		public_key = cert.public_key()
		key = ''.join(random.choice(string.ascii_uppercase +
				string.digits) for _ in range(10))
		print('key to be shared is: ',key)
		message = key.encode('ascii')

		ciphertext = public_key.encrypt(
			message,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		print(ciphertext)
		
		stamp = True
		attempt = 0
		while(stamp):
		
			s.send(base64.b64encode(ciphertext))
			
			print('key sent') 
			       
				
			t = time()
			print(s.recv(1024).decode('ascii'))
			t2 = time()
				
			tt = round((t2-t)*1000,2)
			delay = 1000
		
			print('Timeout time: ',delay)
			print('Delay is:' ,tt)

			if(tt>1000):
				attempt = attempt + 1
				if(attempt == 1):
					no_rtattempt = False
					print('attempt1')
					s.send('resend'.encode('ascii'))
					sleep(1)
					continue
				else:
					no_retransmission = False
					availability = False
					no_delay = False
					delay_val = 100
					stamp = False
					print ('timed out')
					s.send('exit'.encode('ascii'))
				
				
			else:
				s.send('proceed'.encode('ascii'))
				stamp = False
				
				if(tt>100 and tt<200):
					delay_val = tt-100
					delay_val = round(delay_val,2)
					no_delay = False
				elif(tt>=200):
					delay_val = 100
					no_delay = False

				print(delay_val)
			
			
		
		if(no_retransmission):
			while True: 
		
				msg = str(input("Enter message: "))
				a = AesCrypt()
				c = a.encrypt(key,msg)
				s.send(c)
				print('message sent')

				data = s.recv(1024)
				d = a.decrypt(key,data)
				print('message received: ', d.decode('utf-8'))
		
			
				ans = input('\nDo you want to continue(y/n) :') 
				if ans == 'y': 
					continue
				else: 
					break

	data =  {'host_ipaddress':get_primary_ip(),'eval_ipaddress':host,'availability':availability,'ca_certificate':ca_certificate,'no_retransmission':no_retransmission,'no_rtattempt':no_rtattempt,'no_delay':no_delay,'delay_val':delay_val}
	# close the connection 
	data = json.dumps(data)
	r = requests.post(urlp, data, headers=headers)
	print(data)
	s.close()
	
	
