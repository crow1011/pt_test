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



def save_one(rnet, report_path, only_24_32):
	with open(report_path, 'a') as f:
		if only_24_32:
			# если длина префикса 24 - записываем
			if rnet.prefixlen==24:
				f.write(str(rnet) + '\n')
			# если длина префикса 32 - записываем
			elif rnet.prefixlen==32:
				f.write(str(rnet) + '\n')
			# если длина префикса меньше 24 - делим на части по 24 маске и записываем циклом
			elif rnet.prefixlen<24:
				g_net_list = rnet.subnets(new_prefix=24)
				for g_net in g_net_list:
					f.write(str(g_net) + '\n')
			# если длина префикса больше 24 - делим на части по 32 маске и записываем циклом
			elif rnet.prefixlen>24:
				g_net_list = rnet.subnets(new_prefix=32)
				for g_net in g_net_list:
					f.write(str(g_net) + '\n')
		else:
			f.write(str(rnet) + '\n')


def rec_filter(anet, n_deny,report_path, only_24_32):
	overlaps_status = False
	for dnet in n_deny:
		# проверяем пересечение со всеми сетями из deny
		if dnet.supernet_of(anet):
			overlaps_status = True
		elif anet.overlaps(dnet):
			# если пересечение обнаружено меняем статус на False, эта сеть не будет записана
			overlaps_status = True
			# исключаем пересечение и запускаем рекурсию по разбитой сети
			no_overlap = list(anet.address_exclude(dnet))
			for net in no_overlap:
				rec_filter(net, n_deny, report_path, only_24_32)
	# если сеть не имеет пересечений, отправляем на запись
	if not overlaps_status:
		save_one(anet, report_path, only_24_32)



def main(allow_list_path, deny_list_path, only_24_32, report_path):
	#  очищаем файл с результатами
	with open(report_path, 'w') as f:
		pass
	# получаем списки deny и allow
	n_allow = get_net_list(allow_list_path)
	n_deny = get_net_list(deny_list_path)
	# запускаем рекурсию по элементам n_allow
	for anet in n_allow:
		rec_filter(anet, n_deny, report_path, only_24_32)



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
