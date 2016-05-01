#encode = utf-8
from net import is_ip, is_iprange, is_cidrip, is_port, is_multi_port
class Rule(object):

	M_EXT = {
			'multi_src_addr':'-m iprange --src-range',
			'multi_dst_addr':'-m iprange --dst-range',
			'comment':'-m comment --comment',
			'multi_dst_port':'-m multiport --dports'
			}

	CMD = {'append':'A'}

	CHAIN = {'preroute':'PREROUTING', 
			'postroute':'POSTROUTING'
			}

	PROTO = ['tcp', 'udp']	

	TARGET = ['SNAT', 'DNAT', 'ACCEPT']	

	def __init__(self):
		self.rule = {}

	def command(self, cmd):
		if cmd in self.CMD.keys():
			self.rule.update({'cmd': self.CMD[cmd]})
		else:
			raise Exception, "Unavalible parameter %s" % cmd

	def chain(self, name):
		if name in self.CHAIN:
			self.rule.update({'chain': self.CHAIN[name]})
		else:
			raise Exception, "Unavalible parameter %s" % name

	def src_addr(self, addr):
		if is_ip(addr) or is_cidrip(addr):
			self.rule.update({'src_addr':(False, addr)})
		elif is_iprange(addr):
			self.rule.update({'src_addr': (True, addr)})
		else:
			raise Exception, "Illegal address %s" % addr
	def dst_addr(self, addr):
		if is_ip(addr) or is_cidrip(addr):
			self.rule.update({'dst_addr':(False, addr)})
		elif is_iprange(addr):
			self.rule.update({'dst_addr': (True, addr)})
		else:
			raise Exception, "Illegal address %s" % addr

	def protocal(self, proto):
		if proto in self.PROTO:
			self.rule.update({'proto':proto})
		else :
			raise Exception, '%s is not supported!' % proto

	def out_interface(self, interface):
		self.rule.update({'out_int':interface})

	def dport(self, port):
		if not is_multi_port(port)[0] :
			flag = 1
		elif is_multi_port(port)[0]:
			flag = 0
		if 'proto' in self.rule.keys():
			if self.rule['proto'].lower() not in ['tcp', 'udp']:
				raise Exception, "This protocal is need not a port!"
		else:
			self.rule.update({'proto':'tcp'})
		if flag :
			self.rule.update({'dport':(False, port)}) 
		if not flag:
			self.rule.update({'dport': (True, port.replace('-',':'))})

	def target(self, action):
		if action in self.TARGET:
			self.rule.update({'target': action})
		else:
			raise Exception, '%s is not supported!' % action

	def nat_addr(self, addr):
		if 'target' not in self.rule.keys():
			raise Exception, 'Please set NAT target first!'	
		elif self.rule['target'] not in ['SNAT', 'DNAT']:
			raise Exception, 'NAT address is only used for SNAT or DNAT!'
		else:
			self.rule.update({'nat_addr': addr})	

	def comment(self, text):
		self.rule.update({'comment':'"'+text+'"'})

	def generate(self):
		#**************Data Structure!*****************
		#{'cmd':'A', 
		#'chain':'POSTROUTING',
		#'src_addr':(multi=True, '10.0.0.0'),
		#'dst_addr':(multi=False, '20.0.0.0'),
		#'proto':'tcp',
		#'dport':(multi=Flase,'80'),
		#'out_int':'eth0'
		#'target':'SNAT',
		#'nat_addr':'1.1.1.1',
		#'comment':'Hello!' }
		#**********************************************
		
		#para_order = ['cmd', 'chain', 'src_addr', 'dst_addr', 'proto', 'dport', 'out_int', target', 'comment']
		
		_rule = []
		rl_tmp = self.rule
		rule_keys = self.rule.keys()

		#**********************************************
		# 			 Generate the rule
		#**********************************************

		#Necessary 'self.CMD'
		try :
			_rule.append('-'+ rl_tmp['cmd'])
		except Exception as err:
			raise Exception, err
		#Necessary 'self.CHAIN'
		try :
			_rule.append(rl_tmp['chain'])
		except Exception as err:
			raise err
		#Optional 'SRC_ADDR'
		try :
			if rl_tmp['src_addr'][0] == False:
				_rule.append('-s '+ rl_tmp['src_addr'][1])
			elif rl_tmp['src_addr'][0] == True:	
				_rule.append(self.M_EXT['multi_src_addr'] +' '+ rl_tmp['src_addr'][1])
		except :
			pass
		#Optional 'DST_ADDR'	
		try :
			if rl_tmp['dst_addr'][0] == False:
				_rule.append('-d '+ rl_tmp['dst_addr'][1])
			elif rl_tmp['dst_addr'][0] == True:	
				_rule.append(self.M_EXT['multi_dst_addr'] +' '+ rl_tmp['dst_addr'][1])
		except :
			pass
		#Optional 'self.PROTO'	
		try :
			_rule.append('-p '+ rl_tmp['proto'])
		except :
			pass
		#Optional 'DPORT'	
		try :
			if rl_tmp['dport'][0] == False:
				_rule.append('--dport '+ rl_tmp['dport'][1])
			elif rl_tmp['dport'][0] == True:	
				_rule.append(self.M_EXT['multi_dst_port'] +' '+ rl_tmp['dport'][1])
		except :
			pass

		#Optional 'OUT_INT'
		try :
			_rule.append('-o '+ rl_tmp['out_int'])
		except :
			pass

		#Necessary 'self.TARGET'		
		try :
			if rl_tmp['target'] in ['SNAT', 'DNAT'] :
				_rule.extend(['-j '+rl_tmp['target'],'--to-source '+rl_tmp['nat_addr']])
			else:	
				_rule.append('-j '+rl_tmp['target'])
		except Exception as err:
			raise Exception, err
		#Optional 'COMMENT'	
		try :
			_rule.append(self.M_EXT['comment'] +' '+ rl_tmp['comment'])
		except :
			pass

		return _rule

	def rule2str(self):
		return ' '.join(self.generate())								

