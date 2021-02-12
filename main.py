# -*- coding: utf-8 -*-
from ipaddress import ip_address, ip_network
import argparse
import random
import socket
from select import select

# включение и отключение дебага
debug = False

tasks = []
to_write = {}
to_read = {}
res_dict = {}


def get_net_list(fname):
    """
    Генерирует списки с подсетями из файла
    """
    res = []
    with open(fname, 'r') as f:
        net_list = f.read().split('\n')
    for net in net_list:
        try:
            if '/' in net:
                res.append(ip_network(net))
            else:
                res.append(ip_network(net + '/32'))
        except ValueError:
            print('Missing invalid address(ignore):', net)
    return res


def to_net(block):
    """
     Приводит числовое представление нескольких ip к строковому
     Пример: [[0, 24], [167772160, 24]
     вернет:
     0.0.0.0/24
     10.0.0.0/24
    """
    res = []
    for net in block:
        addr = ip_address(net[0])
        net = str(addr) + '/' + str(net[1])
        res.append(net)
    fres = '\n'.join(res)
    return fres


def add_result(rnet):
    """
    Добавляет результат allow списка после очистки
    результат будет добавлен к словарю где ключ - это маска, \
    а значение - это список сетей с такой маской
    """
    if rnet.prefixlen not in res_dict.keys():
        res_dict[rnet.prefixlen] = []
    res_dict[rnet.prefixlen].append([int(rnet[0]), rnet.prefixlen])


def rec_filter(anet, n_deny, only_mask):
    """
    Проходит рекурсивно по всему списку allow
    Если сеть из allow будет разбита на несколько частей, то отправит части на перепроверку
    Если сеть deny является super net для сети из allow, сеть из allow будет отброшена
    Если сеть из allow не пересеекается с сетями из deny, то сеть из allow будет записана в результат
    Если задан параметр максимальной маски, сеть будет разбита по ней
    Если параметр максимальной маски больше маски подсети из allow, она будет разбита по маске 32
    """
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
                rec_filter(net, n_deny, only_mask)
    # если сеть не имеет пересечений, отправляем на запись
    if not overlaps_status:
        if only_mask:
            # если длина префикса 24 - записываем
            if anet.prefixlen == only_mask:
                add_result(anet)
            # если длина префикса 32 - записываем
            elif anet.prefixlen == 32:
                add_result(anet)
            # если длина префикса меньше 24 - делим на части по 24 маске и записываем циклом
            elif anet.prefixlen < only_mask:
                g_net_list = anet.subnets(new_prefix=only_mask)
                for g_net in g_net_list:
                    add_result(g_net)
            # если длина префикса больше 24 - делим на части по 32 маске и записываем циклом
            elif anet.prefixlen > only_mask:
                g_net_list = anet.subnets(new_prefix=32)
                for g_net in g_net_list:
                    add_result(g_net)
        else:
            if anet.prefixlen not in res_dict.keys():
                res_dict[anet.prefixlen] = []
            res_dict[anet.prefixlen].append([int(anet[0]), anet.prefixlen])


def gen_blocks(allow_list_path, deny_list_path, only_mask):
    # получаем списки deny и allow
    n_allow = get_net_list(allow_list_path)
    n_deny = get_net_list(deny_list_path)
    # запускаем рекурсию по элементам n_allow для наполнения res_dict
    for anet in n_allow:
        rec_filter(anet, n_deny, only_mask)
    # Перемешиваем сети в res_dict
    for key, val in res_dict.items():
        random.shuffle(res_dict[key])
    """
    выстраиваем очередь по ключам res_dict
    это нужно для того, чтобы воркеры получали сети от больших к меньшим
    разбивка по маскам нужна, чтобы каждый воркер получал примерно одинаковый объем сетей 
    за одно обращение
    """
    block_masks_queue = sorted(res_dict.keys())
    nets = []
    for mask in block_masks_queue:
        nets += res_dict[mask]
    # создаем словарь в котором будут храниться парометры для блочной итерации по всем сетям
    # сети расположены в порядке убывания, например: [перемешанные сети с маской 24, .. , перемешанные сети с маской 32]
    mon = {}
    mon['length'] = len(nets)
    mon['block_count'] = len(nets) // block_len
    if len(nets) % block_len != 0:
        mon['block_count'] += 1
    mon['last_block_end'] = 0

    for i in range(mon['block_count']):
        block = nets[mon['last_block_end']:mon['last_block_end'] + block_len]
        mon['last_block_end'] += block_len
        if block:
            # возвращаем сети в строковом формате
            yield to_net(block)


def server(blocks):
    """
    код из курса Олега Молчанова
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 5000))
    server_socket.listen()
    while True:
        yield ('read', server_socket)
        client_socket, addr = server_socket.accept()  # read

        print('Connection from', addr)
        tasks.append(client(client_socket, blocks))


def client(client_socket, block):
    while True:
        yield ('read', client_socket)
        request = client_socket.recv(4096)  # read

        if not request:
            break
        else:
            yield ('write', client_socket)
            # отлавливаем StopIteration, воркер должен ожидать такого поведения
            try:
                response = str(next(block)).encode()
            except StopIteration:
                response = 'end of blocks'.encode()
            client_socket.send(response)

    client_socket.close()


def event_loop():
    while any([tasks, to_read, to_write]):
        while not tasks:
            ready_to_read, ready_to_write, _ = select(to_read, to_write, [])
            for sock in ready_to_read:
                tasks.append(to_read.pop(sock))
            for sock in ready_to_write:
                tasks.append(to_write.pop(sock))
        try:
            task = tasks.pop(0)
            reason, sock = next(task)
            if reason == 'read':
                to_read[sock] = task
            if reason == 'write':
                to_write[sock] = task
        except StopIteration:
            print('All Done!')


if __name__ == '__main__':
    if debug:
        allow_list_path = 'data/allow.list'
        deny_list_path = 'data/deny.list'
        only_mask = None
        block_len = 4
    else:
        # парсим параметры
        parser = argparse.ArgumentParser(description='Exclude deny networks in allow networks.')
        parser.add_argument('allow_list', type=str, help='Set path to allow networks list')
        parser.add_argument('deny_list', type=str, help='Set path to deny networks list')
        parser.add_argument('-m', type=str, help='Max network mask. Default: Disable.', default=None)
        parser.add_argument('-b', type=str, help='Max networks in one block. Default: 4.', default=4)
        args = parser.parse_args()
        allow_list_path = args.allow_list
        deny_list_path = args.deny_list
        only_mask = int(args.m)
        block_len = int(args.b)
    # создаем генератор с блоками
    blocks = gen_blocks(allow_list_path, deny_list_path, only_mask)
    # отдаем генератор серверу, будет отдавать его воркерам
    print('Ready to accept connections')
    tasks.append(server(blocks))
    # запуск цикла событий
    event_loop()
