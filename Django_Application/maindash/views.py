import json
from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.http import StreamingHttpResponse
import requests
from django.db import IntegrityError
from .models import ID,cred,Document,Devts,Evalts
from django.contrib.auth.hashers import make_password
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID 
import datetime
from os import stat, remove
from time import time, process_time
import uuid
import os
import errno
import pyAesCrypt
import base64
import objcrypt
from .f22 import *
from .forms import *
from django.core.files.storage import FileSystemStorage
# from .sample import tt_keygen,tt_sign,tt_total 
from .sample import time1,time2,time3,time4 
import string 
import random 
from django.utils.datastructures import MultiValueDictKeyError

def index(request):
	if request.method=='POST':
		
		received=json.loads(request.body.decode("utf-8"))
		hostname=received['hostname']
		ipaddress=received['ipaddress']
		print ('hostname: %s' % hostname)
		print ('ipaddress: %s' % ipaddress)
		filename = ipaddress + "/passkey.txt"
		if not os.path.exists(os.path.dirname(filename)):
			try:
				os.makedirs(os.path.dirname(filename))
			except OSError as exc: # Guard against race condition
				if exc.errno != errno.EEXIST:
					raise
		
		try:
			N = 10 
			res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k = N)) 
			p = ID(hostname=hostname, ipaddress=ipaddress,passkey=res)
			p.save()
			with open(filename, "w") as f:
				f.write(str(res))
		except IntegrityError as e:
			N = 10 
			res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k = N)) 
			obj = ID.objects.get(ipaddress=ipaddress)
			obj.passkey = str(res)
			obj.save()
			with open(filename, "w") as f:
				f.write(str(res))
			print('Details of this IP already exists')
		
		return HttpResponse(res)
	details_list= ID.objects.all()

	return render(request,'index.html',{'details': details_list})
	
	return HttpResponse('')

def checkip(request):
	if request.method=='POST':
		
		received=json.loads(request.body.decode("utf-8"))
		ipaddress=received['ipaddress']
		print ('ipaddress: %s' % ipaddress)
		try:
			obj = ID.objects.get(ipaddress=ipaddress)
			return HttpResponse('IPaddress registered')
		except:
			return HttpResponse('Unregistered IPaddress')

def credential(request):
	details_list= ID.objects.all()
	return render(request,'form.html',{'details': details_list})

def deletecreds(request):
	try:
		ip = request.POST['ipaddr']
	except MultiValueDictKeyError:
		return HttpResponse('please select an IPaddress from the list')

	try:
		cred_store = cred.objects.get(ipaddress=ip)
		cred_store.delete()
		return HttpResponse("credential deleted for this IP")
	except cred.DoesNotExist:
		return HttpResponse("No credential exist for this IP")

def fetch(request):
	
	username=request.POST['username']
	password=request.POST['password']
	# password = make_password(password_nohash, None, 'md5')
	try:
		ip = request.POST['ip']
	except MultiValueDictKeyError:
		return HttpResponse('please select an Ipaddress from the list')	
	try:
		q = cred(username=username,password=password,ipaddress=ip)
		q.save()
		return HttpResponse('crediantial saved')
	except IntegrityError as e:
		cred_store = cred.objects.get(ipaddress=ip)
		cred_store.username=username
		cred_store.password=password
		cred_store.save()
		return HttpResponse('crediantial updated')
	except AssertionError as a:
		return HttpResponse('Both username and password required')

		
		
	# cred={"username":username,"password":password,"ip":ip}
	# cred_json=json.dumps(cred)
	
	# return render(request,'confirm.html',{'cj':cred_json})	
def sendcs(request):
	if request.method=="POST":
		received=json.loads(request.body.decode("utf-8"))
		ipaddress=received['ipaddress']
		print ('ipaddress: %s' % ipaddress)
		filename = ipaddress + "/passkey.txt"
		
		with open(filename, "r") as f:
				passkey = f.read()
		print(str(passkey))
		try:
			cd= cred.objects.get(ipaddress=ipaddress)
			cre={"username":cd.username,"password":cd.password}
			cred_json=json.dumps(cre)
			crypter = objcrypt.Crypter(str(passkey), 'cbc')
			enc_json = crypter.encrypt_json(cred_json)
			return HttpResponse(enc_json)
		except cred.DoesNotExist:
			return HttpResponse('no-credentials')
	return HttpResponse('')
def custcert(request):
	
	return render(request,'custcertform.html')

algo = 'RSA'
value = ec.SECP256R1()
size = 2048
check = 'custom'
security = 'Level 1'
def savecustcert(request):
	global size
	global value
	global algo
	global check
	global security
	try:
		algo = request.POST['algo']
	except MultiValueDictKeyError:
		algo='RSA'
	try:
		security = request.POST['security']
	except MultiValueDictKeyError:
		return HttpResponse('please select a security level from the list')
	check = 'NA'
    
	if(algo == 'ECC'):
		if(security == 'Level 1'):
			value = ec.SECP192R1()
		elif(security == 'Level 2'):
			value = ec.SECP224R1()
		else:
			value = ec.SECP256R1()
	elif(algo == 'RSA'):
		if(security == 'Level 1'):
			size = 1024
		elif(security == 'Level 2'):
			size = 2048
		else:
			size = 3072
	
			
	return HttpResponse('values set')
def fileupload(request):
    # Handle file upload
    # global check
    # check =  'custom'
    if request.method == 'POST':
    	try:
    		myfile = request.FILES['sample.py']
    		fs = FileSystemStorage()
    		if(fs.exists(myfile.name)):
    			fs.delete(myfile.name)
    		filename = fs.save(myfile.name, myfile)
    		uploaded_file_url = fs.url(filename)
    		return HttpResponse("File uploaded")
    	except MultiValueDictKeyError:
        	return HttpResponse('No file to upload')
    return HttpResponse('File uploaded')

# def renderupload(request):
	
	# if request.method == "POST":
		# check = request.POST['check']
		# return render(request,'upload.html')

def testcustcert(request):
	global size
	global value
	global algo
	global check
	global security
	t = process_time()
	# print(t)
	# print("sep")
	one_day = datetime.timedelta(1, 0, 0)
	if(check == 'NA'):
		if(algo == 'ECC'):
			private_key = ec.generate_private_key(
        	value, default_backend()
    		)
		else:
			private_key = rsa.generate_private_key(
    		public_exponent=65537,
    		key_size=size,
    		backend=default_backend()
			)
		t2 = process_time()
		# print(t2)
		public_key = private_key.public_key()
		builder = x509.CertificateBuilder()
		builder = builder.subject_name(x509.Name([
    		x509.NameAttribute(NameOID.COMMON_NAME, u'CA certificate'),
    		
		]))
		builder = builder.issuer_name(x509.Name([
    		x509.NameAttribute(NameOID.COMMON_NAME, u'Self signed'),
		]))
		builder = builder.not_valid_before(datetime.datetime.today() - one_day)
		builder = builder.not_valid_after(datetime.datetime(2020, 8, 2))
		builder = builder.serial_number(int(uuid.uuid4()))
		builder = builder.public_key(public_key)
		builder = builder.add_extension(
    		x509.BasicConstraints(ca=True, path_length=None), critical=True,
		)
		t3=process_time()
		certificate = builder.sign(
    		private_key=private_key, algorithm=hashes.SHA256(),
    		backend=default_backend()
		)
		t4 = process_time()
		# print(isinstance(certificate, x509.Certificate))

		return HttpResponse("Algorithm used is %s" % algo + " with %s" % security + " security"'<p>' +"Time taken for certificate generation is %f" % (t4-t) + " seconds" '<br>' "Time taken for key generation is %f" % (t2-t) + " seconds" '<br>' "Time taken for signing is %f" % (t4-t3) + " seconds")
	else:
		# return HttpResponse("Algorithm used is user-defined" + '<p>' + "Time taken for certificate generation is %f" % (tt_total) + " seconds"'<br>' "Time taken for key generation is %f" % (tt_keygen) + " seconds" '<br>' "Time taken for signing is %f" % (tt_sign) + " seconds")
		return HttpResponse("Algorithm used is user-defined" + '<p>' + "Time taken for certificate generation is %f" % (time4-time1) + " seconds"'<br>' "Time taken for key generation is %f" % (time2-time1) + " seconds" '<br>' "Time taken for signing is %f" % (time4-time3) + " seconds")
def certgen(request):
	if request.method == "POST": 
		received=json.loads(request.body.decode("utf-8"))
		ipaddress=received['ipaddress']
		try:
			reg_list = ID.objects.get(ipaddress=ipaddress)
		except ID.DoesNotExist:
			return HttpResponse('not-registered')
		one_day = datetime.timedelta(1, 0, 0)
		# print('algo:%s' % algo)
		# print('value:%s' % value)
		
		
		private_key = rsa.generate_private_key(
    		public_exponent=65537,
    		key_size=size,
    		backend=default_backend()
		)
			# if(algo == 'ECC'):
				# private_key = ec.generate_private_key(
        		# value, default_backend()
    			# )
			# else:
				
		public_key = private_key.public_key()
		builder = x509.CertificateBuilder()
		builder = builder.subject_name(x509.Name([
    		x509.NameAttribute(NameOID.COMMON_NAME, u'CA certificate'),
    		
		]))
		builder = builder.issuer_name(x509.Name([
    		x509.NameAttribute(NameOID.COMMON_NAME, u'Self signed'),
		]))
		builder = builder.not_valid_before(datetime.datetime.today() - one_day)
		builder = builder.not_valid_after(datetime.datetime(2020, 8, 2))
		builder = builder.serial_number(int(uuid.uuid4()))
		builder = builder.public_key(public_key)
		builder = builder.add_extension(
    		x509.BasicConstraints(ca=True, path_length=None), critical=True,
		)
		certificate = builder.sign(
    		private_key=private_key, algorithm=hashes.SHA256(),
    		backend=default_backend()
		)
		print(isinstance(certificate, x509.Certificate))
		
		filename1 = ipaddress + "/ca.key"
		filename2 = ipaddress + "/ca.crt"
		
		if not os.path.exists(os.path.dirname(filename2)):
			try:
				os.makedirs(os.path.dirname(filename2))
			except OSError as exc: # Guard against race condition
				if exc.errno != errno.EEXIST:
					raise

		with open(filename1, "wb") as f:
			f.write(private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
        		# encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        		encryption_algorithm=serialization.NoEncryption()
    		))

		with open(filename2, "wb") as f:
			f.write(certificate.public_bytes(
				encoding=serialization.Encoding.PEM,
    		))
		bufferSize = 64 * 1024
		filename = ipaddress + "/passkey.txt"
		with open(filename, "r") as f:
				password = f.read()
		# encrypt
		with open(filename1, "rb"):
			pyAesCrypt.encryptFile(filename1, ipaddress + "/ca.key.aes", password, bufferSize)	
	
		# data = open(ipaddress + "/ca.key.aes", "r").read()
		# data.encode('utf-8').strip()
		# encoded = base64.b64encode(data)
		# print (data)		
		# pyAesCrypt.encryptFile(filename1, ipaddress + "/ca.key.aes", password, bufferSize)
		# pyAesCrypt.encryptFile(ipaddress + "/key.txt", ipaddress + "/key.txt.aes", password, bufferSize)
		# pyAesCrypt.decryptFile(ipaddress + "/ca.key.aes", ipaddress + "/cad.key", password, bufferSize)
		return HttpResponse('success')

def sendca(request):

	if request.method == "POST": 
		received=json.loads(request.body.decode("utf-8"))
		ipaddress=received['ipaddress']
		filename = ipaddress + "/ca.crt"
		try:
			with open(filename, 'r') as f:
				file_data = f.read()
		except FileNotFoundError : 
			return HttpResponse('FileNotFound')
		response = HttpResponse(file_data, content_type='application/pkix-cert')
		response['Content-Disposition'] = 'attachment; filename="ca.cert"'
		return response

def sendkey(request):

	if request.method == "POST": 
		received=json.loads(request.body.decode("utf-8"))
		ipaddress=received['ipaddress']
		filename = ipaddress + "/ca.key.aes"
		with open(filename, 'rb') as f:
			file_data = f.read()
		response = HttpResponse(file_data, content_type='application/octet-stream' )
		# response['Content-Length'] = len(file_data.encode('utf-8'))
		# response.__init__(charset='utf-8')
		response['Content-Disposition'] = 'attachment; filename="ca.key.aes"'
		return response



def download(request):
   
        with open("Instructions.pdf", 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/pdf")
            response['Content-Disposition'] = 'inline; filename="Instructions.pdf"'
            return response

def getparams(request):

	if request.method == "POST":

		received=json.loads(request.body.decode("utf-8"))
		ipaddr = received['ipaddress'] 
		print(ipaddr)
		open_connections = received['open_connections']
		open_connections = (open_connections/131070)*100
		open_connections = 100-round(open_connections,2)
		print ('open connections value:',open_connections)
		active_processes = received['active_processes']
		process_limit = received['process_limit']
		active_plimit = (active_processes/process_limit)*100
		active_plimit = 100-round(active_plimit,2)
		print ('active processes value:',active_plimit)
		cpu_vulnerability = received['cpu_vulnerability']
		cpu_val = 100
		if(cpu_vulnerability == 'True'):
			cpu_val = 0
		elif(cpu_vulnerability == 'None'):
			cpu_val=50
		print('cpu vulnerability value:',cpu_val)
		se_val = 100
		selinux_status = received['selinux_status']
		selinux_mode = received['selinux_mode']
		if(not selinux_status):
			se_val = 0
		else:
			if(selinux_mode == 'None'):
				se_val = 0
			elif(selinux_mode == 'permissive'):
				se_val = 50
		# print (se_val)
		aa_val = 100
		app_armour = received['app_armour']
		if(not app_armour):
			aa_val = 0
		# print (aa_val)
		appsec_val =100
		if(se_val>aa_val):
			appsec_val = se_val
		else:
			appsec_val = aa_val
		print('SElinux/AppArmour value:',appsec_val)
		try:
			params = Devts(ipaddress=ipaddr, connections=open_connections,processes=active_plimit,vulnerability=cpu_val,systemsec=appsec_val)
			params.save()
		except IntegrityError as e:
			params = Devts.objects.get(ipaddress=ipaddr)
			params.connections = open_connections
			params.processes = active_plimit
			params.vulnerability = cpu_val
			params.systemsec = appsec_val
			params.save()
		# params = Devts.objects.get(ipaddress=ipaddr)
		# print(params.connections)
		# print(params.processes)
		# print(params.vulnerability)
		# print(params.systemsec)
	return HttpResponse('')
def getvals(request):
	if request.method == "POST":

		received=json.loads(request.body.decode("utf-8"))
		eval_ip = received['host_ipaddress']
		host_ip = received['eval_ipaddress']
		avail_val = 0
		availability = received['availability']
		if(availability):
			avail_val = 100
		print('Availabilty value:',avail_val)
		ca_certval = 0
		ca_cert = received['ca_certificate']
		if(ca_cert):
			ca_certval = 100
		print('Certificate value:',ca_certval)
		retrans_val = 0 
		no_retransmission = received['no_retransmission']
		no_rtattempt = received['no_rtattempt']
		if(no_retransmission):
			if(no_rtattempt):
				retrans_val = 100
			else:
				retrans_val = 50
		print('Retransmission value:',retrans_val)
		d_val  = 0
		no_delay = received['no_delay']
		delay_val = received['delay_val']
		if(no_delay):
			d_val = 100
		else:
			d_val = 100-delay_val
		print('Delay value:',d_val)
		try:
			params1 = Evalts.objects.get(host_ipaddress=host_ip)
			params2 = Evalts.objects.get(host_ipaddress=eval_ip)
			if(params1.trustscore <= params2.trustscore ):
				# print('if')
				params1.availability = avail_val
				params1.certificate = ca_certval
				params1.retransmission = retrans_val 
				params1.delay =  d_val
				params1.eval_ipaddress = eval_ip
				params1.save()
			# else:
			# 	print('else')
		except Evalts.DoesNotExist:
				try:
					# print('first update')
					params1 = Evalts(host_ipaddress = host_ip,availability = avail_val,certificate = ca_certval,retransmission = retrans_val,delay =  d_val,eval_ipaddress = eval_ip,trustscore=0 )
					params1.save()
				except IntegrityError:
					# print('IE')
					if(params1.trustscore == 0):
						params1 = Evalts.objects.get(host_ipaddress=host_ip)
						params1.availability = avail_val
						params1.certificate = ca_certval
						params1.retransmission = retrans_val 
						params1.delay =  d_val
						params1.eval_ipaddress = eval_ip
						params1.save()
		print('Entries in DB')
		params1 = Evalts.objects.get(host_ipaddress=host_ip)
		print(params1.host_ipaddress)
		print(params1.availability)
		print(params1.certificate)
		print(params1.retransmission) 
		print(params1.delay) 
		print('Device Trustscore:',params1.trustscore)
		print('Evaluator Trustscore:',params2.trustscore)
		# print(params1.eval_ipaddress)
	return HttpResponse('')
def weights(request):
	details_list= ID.objects.all()
	return render(request,'tscalc.html',{'details': details_list})
def computets(request):
	try:
		ip = request.POST['ip']
	except MultiValueDictKeyError:
		return HttpResponse('please select an IPaddress from the list')
	try:
		paramsd = Devts.objects.get(ipaddress= ip)
		paramse = Evalts.objects.get(host_ipaddress=ip)
	except Devts.DoesNotExist:
		return HttpResponse('Device Parameters does not exist for the selected Ipaddress')
	except Evalts.DoesNotExist:
		return HttpResponse('Eval Parameters does not exist for the selected Ipaddress')	
	
	d1 = float(request.POST['opc'])
	d2 = float(request.POST['nop'])
	d3 = float(request.POST['cv'])
	d4 = float(request.POST['sa'])
	e1 = float(request.POST['av'])
	e2 = float(request.POST['ca'])
	e3 = float(request.POST['rt'])
	e4 = float(request.POST['dl'])
	w = (d1+d2+d3+d4+e1+e2+e3+e4)
	if(round(w,0)!=1):
		return HttpResponse('weights dont add upto 1')
	trustscored = d1*float(paramsd.connections) + d2*float(paramsd.processes) + d3*float(paramsd.vulnerability) + d4*float(paramsd.systemsec)
	trustscoree = e1*float(paramse.availability) + e2*float(paramse.certificate) + e3*float(paramse.retransmission) + e4*float(paramse.delay)
	trustscore = round((trustscored+trustscoree),0) 
	paramse.trustscore = trustscore
	paramse.save()
	# print(paramse.host_ipaddress)
	# print(paramse.trustscore)
	# print(paramse.eval_ipaddress)
	return HttpResponse('Trustscore is: %i' %trustscore)