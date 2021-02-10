from ipaddress import ip_address, ip_network


allow_list_path = 'data/allow.list'
deny_list_path = 'data/deny.list'
only_24 = True

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
			print('Missing invalid address(ignore):', net)
	return res



def save_results(res, report_path):
	with open(report_path, 'w') as f:
		for net in res:
			f.write(str(net) + '\n')


def filter(allow_list_path, deny_list_path, report_path='report.list'):
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

	for rnet in res:
		if only_24:
			print('now', rnet, rnet.prefixlen)
			if rnet.prefixlen==24:
				yield rnet
			elif rnet.prefixlen==32:
				yield rnet
			elif rnet.prefixlen<24:
				g_net_list = rnet.subnets(new_prefix=24)
				for g_net in g_net_list:
					yield g_net
			elif rnet.prefixlen>24:
				g_net_list = rnet.subnets(new_prefix=32)
				for g_net in g_net_list:
					yield g_net
		else:
			yield rnet




if __name__ == '__main__':
	res = filter(allow_list_path=allow_list_path, deny_list_path=deny_list_path)
	save_results(res, 'report.list')