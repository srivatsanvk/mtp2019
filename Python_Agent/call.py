from netstat import *
import subprocess
import netifaces
import json
import requests

def get_primary_ip():
    try:
        primary_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(primary_interface)
        return (addrs[netifaces.AF_INET][0]['addr'])
    except (OSError, KeyError):
        return None

def dparams():
	while(True):
			
		lst = []
		lst = netstat_scan()[1]
		nc = len(lst)
		lst = []
		lst = process_scan()
		np = len(lst)
		cmd = 'ulimit -a > limit.txt'
		os.system(cmd)
		keyword ='process              '
		with open('limit.txt') as fd:
			for line in fd:
				if keyword in line:
					before_keyword,keyword, after_keyword = line.partition(keyword)
					cp = int(after_keyword)
					break
		vuln = str(cpu_vulnerabilities().get('vulnerable'))
		status = selinux_status()
		se = status.get('enabled')
		if 'mode' in status:
			sem = status.get('mode')
		else:
			sem = 'NA'
		aa = is_app_armor_enabled()

		data ={'ipaddress':get_primary_ip() ,'open_connections':nc ,'active_processes':np ,'process_limit':cp ,'cpu_vulnerability':vuln ,'selinux_status':se ,'selinux_mode':sem ,'app_armour':aa }
		data=json.dumps(data)
		print(data)
		url = "http://10.0.2.5:8000/getparams/"
	
		headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
		r = requests.post(url, data, headers=headers)
		time.sleep(1800)
	
	
	
if __name__ == '__main__':
	main()
