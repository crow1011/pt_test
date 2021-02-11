# -*- coding: utf-8 -*-
from ipaddress import ip_address, ip_network
import argparse

# включение и отключение дебага
debug = False



def get_net_list(fname):
	res = []
	# читаем файл и разбиваем по строкам
	with open(fname, 'r') as f:
		net_list = f.read().split('\n')
	# инкапсулируем строковый адрес в объект ip_network
	for net in net_list:
		try:
			if '/' in net:
				res.append(ip_network(net))
			else:
				# добавляем маску если адрес одиночный
				res.append(ip_network(net+'/32'))
		except ValueError:
			# если попадется невалидный адрес в списке, он будет проигнорирован
			print('Missing invalid address(ignore):', net)
	return res



def save_results(res, report_path):
	with open(report_path, 'w') as f:
		for net in res:
			# пишет построчно из генератора
			f.write(str(net) + '\n')


def net_filter(n_allow, n_deny, only_24_32):
	# подготавливаем список для результатов
	res = []
	for anet in n_allow:
		# задаем статус для сети из allow списка в False, если статус не изменится, она будет добавлена в res
		overlaps_status = False
		for dnet in n_deny:
			# проверяем пересечение со всеми сетями из deny
			if dnet.supernet_of(anet):
				overlaps_status = True
			elif anet.overlaps(dnet):
				# если пересечение обнаружено меняем статус на False, в res сеть не попадет
				overlaps_status = True
				# исключаем пересечение и добавляем результат в конец списка allow, для перепроверки
				no_overlap = list(anet.address_exclude(dnet))
				for net in no_overlap:
					n_allow.append(net)
		# если подсеть не пересекается ни с одной из deny, добавляем в res
		if not overlaps_status:
			res.append(anet)

	for rnet in res:
		# проверяем статус параметра
		if only_24_32:
			# если длина префикса 24 - отдаем
			if rnet.prefixlen==24:
				yield rnet
			# если длина префикса 32 - отдаем
			elif rnet.prefixlen==32:
				yield rnet
			# если длина префикса меньше 24 - делим на части по 24 маске и отдаем циклом
			elif rnet.prefixlen<24:
				g_net_list = rnet.subnets(new_prefix=24)
				for g_net in g_net_list:
					yield g_net
			# если длина префикса больше 24 - делим на части по 32 маске и отдаем циклом
			elif rnet.prefixlen>24:
				g_net_list = rnet.subnets(new_prefix=32)
				for g_net in g_net_list:
					yield g_net
		else:
			yield rnet

def main(allow_list_path, deny_list_path, only_24_32, report_path):
	# получаем списки deny и allow
	n_allow = get_net_list(allow_list_path)
	n_deny = get_net_list(deny_list_path)
	# создаем генератор с отфильтрованными результатами
	gres = net_filter(n_allow, n_deny, only_24_32)
	# сохраняем
	save_results(gres, report_path)



if __name__ == '__main__':
	if debug:
		allow_list_path = 'data/allow.list'
		deny_list_path = 'data/deny.list'
		report_path = 'report.list'
		only_24_32 = False
		main(allow_list_path, deny_list_path, only_24_32, report_path)
	else:
		# парсим параметры
		parser = argparse.ArgumentParser(description='Exclude deny networks in allow networks.')
		parser.add_argument('allow_list', type=str, help='Set path to allow networks list')
		parser.add_argument('deny_list', type=str, help='Set path to deny networks list')
		parser.add_argument('-p', action='store_true', help='Only 24 or 32 network mask. Default: False', default=False)
		parser.add_argument('-o', type=str, help='Path to save report. Default: report.list', default='report.list')
		args = parser.parse_args()
		allow_list_path = args.allow_list
		deny_list_path = args.deny_list
		report_path = args.o
		only_24_32 = args.p
		main(allow_list_path, deny_list_path, only_24_32, report_path)
