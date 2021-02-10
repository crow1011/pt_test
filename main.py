from ipaddress import ip_address, ip_network

def get_allow():
	pass

def get_deny():
	pass

def save_results():
	pass


def main():
	n_allow = get_allow()
	n_deny = get_deny()
	res = []
	for anet in n_allow:
	    print(anet)
	    overlaps_status = False
	    for dnet in n_deny:
	        print(anet.overlaps(dnet), dnet, anet)
	        if anet.overlaps(dnet):
	            overlaps_status = True
	            no_overlap = list(anet.address_exclude(dnet))
	            for net in no_overlap:
	                n_allow.append(net)
	            print(anet.supernet_of(dnet))
	            print(list(anet.address_exclude(dnet)))
	if not overlaps_status:
        res.append(anet)



if __name__ == '__main__':
	main()