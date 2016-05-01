import iptcRule
from ruleData import Policy_instance
#from datetime import date
#apply_date = str(date.today()).replace('-', '')

# Policy_instance = {\
	# 'src_addr':['10.0.0.1-10.0.0.10', '10.0.0.78', '10.0.0.98/31'],
	# 'dst_addr':['1.1.1.1-10', '2.2.2.2', '3.3.3.0/31'],
	# 'protocal':'tcp',
	# 'dport':'80-90',
	# 'out_interface':'',
	# 'applyer':'jjjj@jd.com',
	# 'location':'MJQ',	
	# 'dnat_addr':'222.222.222.222',	
	# 'access_type': 2, #Other values:{'To_internet':1, 'Test_to_Product':2, 'Product_to_Test': 3}
	# 'today_date':apply_date,
	# 'expira_date':'2016-12-01',
# }
SNAT_ADDR = {'MJQ':'172.16.0.1', 'LF':'172.18.0.1', 'HC':'172.20.0.1'}

def generatePolicy(instance):
	src_address = instance['src_addr']
	dst_address = instance['dst_addr']
	_inst = instance.copy()
	_inst.pop('src_addr')
	_inst.pop('dst_addr')
	for src_addr in src_address:
		_inst.update({'src_addr': src_addr})
		for dst_addr in dst_address:
			_inst.update({'dst_addr': dst_addr})
			yield _inst
	return	

def set_default_int(policy):
	if policy['location'] in ['HC']:
		policy.update({'out_interface':'eth0'})
		
def generateRule(policy):
	_rule = iptcRule.Rule()
	_rule.command('append')
	if policy['src_addr'] != '':
		_rule.src_addr(policy['src_addr'])
	if policy['dst_addr'] != '':	
		_rule.dst_addr(policy['dst_addr'])
	if policy['protocal'] != '':
		_rule.protocal(policy['protocal'])
		
	set_default_int(policy)
	if policy['out_interface'] != '':
		_rule.out_interface(policy['out_interface'])
		
	if policy['dport'] != '':
		_rule.dport(policy['dport'])
	if policy['access_type'] == 1 :
		if policy['dnat_addr'] != '':
			_rule.target('DNAT')
			_rule.nat_addr(policy['dnat_addr'])
			_rule.chain('preroute')
		else:
			_rule.target('SNAT')
			_rule.nat_addr(SNAT_ADDR[policy['location']])
			_rule.chain('postroute')
	else :
		_rule.chain('preroute')
		_rule.target('ACCEPT')
		
	comment_text = policy['applyer']+'_'+policy['today_date']+'-'+policy['expira_date']
	_rule.comment(comment_text)
	return _rule.rule2str()

for i in generatePolicy(Policy_instance):
	print generateRule(i)
 
