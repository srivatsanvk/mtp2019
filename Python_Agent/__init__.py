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

from rpi_helper import Confinement, detect_confinement, detect_installation, get_deb_packages

import requests

def host_name():
	myhost = os.uname()[1]
	return (myhost)

def get_primary_ip():
    try:
        primary_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(primary_interface)
        return (addrs[netifaces.AF_INET][0]['addr'])
    except (OSError, KeyError):
        return None


def receive_data():
	url = "http://10.0.2.5:8000/sendcs/"
	data ={'ipaddress': get_primary_ip()}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	with open("passkey.txt","r") as f:
		passkey = f.read()
	crypter = objcrypt.Crypter(passkey, 'cbc')
	print(str(r.text))
	dec_json = crypter.decrypt_json(r.text)
	print(str(dec_json))
	if(str(r.text) != "no-credentials"):
		with open('data.json', 'w') as f:
    			f.write(dec_json)
	else:	
		if os.path.exists("data.json"):
  			os.remove("data.json")

def generate_cert():
	url = "http://10.0.2.5:8000/certgen/"
	data ={'ipaddress': get_primary_ip()}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	print(str(r.text))
	if(str(r.text) != "not-registered"):
		get_cert()

def get_cert():
	get_ca()
	get_key()

def get_ca():
	url = "http://10.0.2.5:8000/sendca/"
	data ={'ipaddress': get_primary_ip()}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	with open('ca.crt', 'w') as f:
    			f.write(r.text)

def get_key():	
	url = "http://10.0.2.5:8000/sendkey/"
	data ={'ipaddress': get_primary_ip()}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	with open('ca.key.aes', 'wb') as f:
		f.write(r.content)
	bufferSize = 64 * 1024
	with open("passkey.txt","r") as f:
		password = f.read()
	pyAesCrypt.decryptFile("ca.key.aes", "ca.key", password, bufferSize)
	

def temp():	
	print(r.encoding)
	with open('ca.key.aes', 'w') as f:
		f.write(r.text)
	with open('ca.key.aes', 'w') as f:
		f.write(r.text)
	bufferSize = 64 * 1024
	password = "password1"
	pyAesCrypt.decryptFile("ca.key.aes", "ca.key", password, bufferSize)


