from ipaddress import ip_address, ip_network
import argparse

debug = False



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
		if only_24_32:
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

def main(allow_list_path, deny_list_path, only_24_32, report_path):
	gres = filter(allow_list_path, deny_list_path, only_24_32)
	save_results(gres, report_path)



if __name__ == '__main__':
	if debug:
		allow_list_path = 'data/allow.list'
		deny_list_path = 'data/deny.list'
		report_path = 'report.list'
		only_24_32 = False
		main(allow_list_path, deny_list_path, only_24_32, report_path)
	else:
		parser = argparse.ArgumentParser(description='Exclude deny networks in allow networks.')
		parser.add_argument('allow_list', type=str, help='Set path to allow networks list')
		parser.add_argument('deny_list', type=str, help='Set name for search in data')
		parser.add_argument('-p', action='store_true', help='Only 24 or 32 network mask. Default: False', default=False)
		parser.add_argument('-o', type=str, help='Path to save report. Default: report.list', default='report.list')
		args = parser.parse_args()
		allow_list_path = args.allow_list
		deny_list_path = args.deny_list
		report_path = args.o
		only_24_32 = args.p
		print(args)
		main(allow_list_path, deny_list_path, only_24_32, report_path)
