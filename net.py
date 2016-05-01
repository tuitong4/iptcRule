#encode = utf-8
def is_ip(str_):
	_ip = str_.split('.')
	if len(_ip) != 4:
		return False 
	for item in _ip:
		try :
			if 	int(item) < 0 or int(item) > 255:
				return False
		except:
			return False
	return True

def ip2long(ip):
	ip_list=ip.split('.')
	if not is_ip:
		return "WRONG IP ADDRESS!"
	return (int(ip_list[0])<<24)+(int(ip_list[1])<<16)+(int(ip_list[2])<<8)+int(ip_list[3])
	
def long2ip(ip_int):
	return str(ip_int>>24)+"."+str((ip_int>>16)&255)+"."+str((ip_int>>8)&255)+"."+str(ip_int&255)
	
def vlsm2mask(vlsm):
	if vlsm<=0 | vlsm>=33:
		return "WRONG MASK LENGHT!"
	return long2ip((4294967295 >> vlsm)^4294967295)
	
def mask2vlsm(mask):
	reverse_ip = ip2long(mask)^4294967295
	if reverse_ip == 0:
		return 32
	i=1	
	while i<33:
		if (reverse_ip >> i)&1==1:
			i=i+1
		elif (reverse_ip >> i)&1==0 and (reverse_ip >> i)!=0:
			return "WRONG MASK!"
		else:
			return 32-i
			
def vlsm2wildmask(vlsm):
	if vlsm<=0 | vlsm>=33:
		return "WRONG VLSM LENGHT!"
	return long2ip(2**(32-vlsm)-1)

def is_iprange(iprange):
	#Right format:10.0.0.1-10, 10.0.0.1-10.0.0.10,
	#Wrong format:10-10.0.0.10
	_ip = iprange.split('-')
	if len(_ip) != 2:
		return False
	
	if is_ip(_ip[0]):
		#Case 1:10.0.0.1-10.0.0.10
		if is_ip(_ip[1]):
			return True
		#Case 2:10.0.0.1-10	
		elif int(_ip[1]) > int(_ip[0].split('.')[3]) and int(_ip[1]) <= 255:
			return True
		else:
			return False	
	else :
		return False

def is_cidrip(cidrip):
	try:
		_ip, _cidr = cidrip.split('/')
	except:
		return False
	if is_ip(_ip) and int(_cidr) >= 0 and int(_cidr) <= 32:
		return True
	else :
		return False	

def is_port(port):
	if isinstance(port, int) and port>0 and port < 65535:
		return True
	else:
		return False

def is_multi_port(port):
	#input port : 80, 80-90, 80,81,83
	if is_port(port):
		return (False, str(port))
	elif isinstance(port, str):
		flag = True
		try:
			beg_port, end_port = port.split('-')
			if is_port(int(beg_port)) and is_port(int(end_port)):
				if beg_port == end_port:
					return (False, beg_port)
				return (True, port)
			else :
				raise Exception, 'Port format is unavalible.'	
		except:
			flag = False
		if not flag :
			try:
				ports = list(set(port.split(',')))
			except:
				raise Exception, 'Port format is unavalible.'
			ports.sort()
			for _port in ports:
				if is_port(int(_port)):
					pass
				else :
					raise Exception, 'Port format is unavalible.'	
			if len(ports) != 1:
				return (True, ','.join(ports))	
			else :
				return (False, ports[0])
		else :
			raise Exception, 'Port format is unavalible.'
	elif is_port(int(port)):
		return (False, port)
	else:
		raise Exception, 'Port format is unavalible.'



		
			
		
		
