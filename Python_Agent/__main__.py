from __init__ import *
from client import *
from server import *
import requests
import json
import time
from call import *


def main():
	print('1.send details 2.get credentials 3.generate cert 4.client 5.server 6.send device parameters')
	x = int(input("Enter choice: "))
	if(x==1):
		send_data()
	elif(x==2):
		while(True):
			receive_data() 
			time.sleep(1800)
	elif(x==3):
		generate_cert()

	elif(x==4):
		client()
	elif(x==5):
		server()
	else:
		dparams()
		
	

def send_data():
	url = "http://10.0.2.5:8000"
	data = {'hostname': host_name(),'ipaddress': get_primary_ip()}
	data1 = {'sender': 'Alice', 'receiver': 'Bob', 'message': 'We did it!'}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post(url, data=json.dumps(data), headers=headers)
	passkey = str(r.text)
	with open("passkey.txt","w") as f:
		f.write(passkey)


if __name__ == '__main__':
	main()
