from datetime import date
apply_date = str(date.today()).replace('-', '')
Policy_instance = {\
	'src_addr':['10.0.0.1-10.0.0.10', '10.0.0.78', '10.0.0.98/31'],
	'dst_addr':['1.1.1.1-10', '2.2.2.2', '3.3.3.0/31'],
	'protocal':'tcp',
	'dport':'80',
	'out_interface':'',
	'applyer':'jjjj@jd.com',
	'location':'MJQ',	
	'dnat_addr':'222.222.222.222',	
	'access_type': 1, #Other values:{'To_internet':1, 'Test_to_Product':2, 'Product_to_Test': 3}
	'today_date':apply_date,
	'expira_date':'2016-12-01',
}
