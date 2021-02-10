from ipaddress import ip_address, ip_network


allow_list_path = 'data/allow.list'
deny_list_path = 'data/deny.list'


# ValueError
def get_net_list(fname):
	res = []
	with open(fname, 'r') as f:
		net_list = f.read().split('\n')
	for net in net_list:
		try:
			if '/' in net:
				res.append(ip_network(net))
			else:
				res.append(ip_network(net+'/32'))
		except ValueError:
			print('Missing invalid address:', net)
	return res



def save_results():
	pass


def main(allow_list_path, deny_list_path, report_path='report.list'):
	n_allow = get_net_list(allow_list_path)
	n_deny = get_net_list(deny_list_path)
	res = []
	for anet in n_allow:
		# print(anet)
		overlaps_status = False
		for dnet in n_deny:
			# print(anet.overlaps(dnet), dnet, anet)
			if anet.overlaps(dnet):
				overlaps_status = True
				no_overlap = list(anet.address_exclude(dnet))
				for net in no_overlap:
					n_allow.append(net)
				# print(anet.supernet_of(dnet))
				# print(list(anet.address_exclude(dnet)))
		if not overlaps_status:
			res.append(anet)

	return res




if __name__ == '__main__':
	print(main(allow_list_path=allow_list_path, deny_list_path=deny_list_path))