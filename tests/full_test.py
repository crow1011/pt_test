# -*- coding: utf-8 -*-
import unittest
from main import get_net_list, net_filter
from ipaddress import IPv4Network
import sys



class ColorPrint:

    def print_fail(self, message, end='\n'):
        sys.stderr.write('\x1b[1;31m' + str(message).strip() + '\x1b[0m' + end)

    def print_pass(self, message, end='\n'):
        sys.stdout.write('\x1b[1;32m' + str(message).strip() + '\x1b[0m' + end)

    def print_warn(self, message, end='\n'):
        sys.stderr.write('\x1b[1;33m' + str(message).strip() + '\x1b[0m' + end)

    def print_info(self, message, end='\n'):
        sys.stdout.write('\x1b[1;34m' + str(message).strip() + '\x1b[0m' + end)

    def print_bold(self, message, end='\n'):
        sys.stdout.write('\x1b[1;37m' + str(message).strip() + '\x1b[0m' + end)


class TestFull(unittest.TestCase, ColorPrint):
    def setUp(self):
        self.allow_list_path = 'data/allow.list'
        self.deny_list_path = 'data/deny.list'
        self.report_path = 'report.list'
        self.only_24_32 = False
        self.n_allow = [IPv4Network('1.0.0.0/8'), IPv4Network('192.168.1.0/24'), IPv4Network('192.168.2.0/24'), IPv4Network('192.168.3.0/24'), IPv4Network('192.168.4.0/24'), IPv4Network('10.0.100.0/24')]
        self.n_deny = [IPv4Network('192.168.2.0/24'), IPv4Network('192.168.3.0/25'), IPv4Network('192.168.0.0/16')]
        self.gres_without_p =  [IPv4Network('1.0.0.0/8'), IPv4Network('10.0.100.0/24')]
        self.data_with_p = IPv4Network('10.10.0.0/23')
        self.gres_with_p = [IPv4Network('10.10.0.0/24'), IPv4Network('10.10.1.0/24')]

    def test_get_addrs(self):
        self.print_info(f'Чтение Allow списка: {self.allow_list_path}')
        self.assertEqual(get_net_list(self.allow_list_path), self.n_allow)
        self.print_pass('..OK')
        self.print_info(f'Чтение Deny списка: {self.deny_list_path}')
        self.assertEqual(get_net_list(self.deny_list_path), self.n_deny)
        self.print_pass('..OK')

    def test_net_filter_without_p(self):
        self.print_info(f'Проверка фильтрации на списках из файлов(без параметра): {self.allow_list_path}, {self.deny_list_path}')
        self.assertEqual(self.gres_without_p, list(net_filter(self.n_allow, self.n_deny, self.only_24_32)))
        self.print_pass('..OK')


    def test_net_filter_with_p(self):
        self.print_info(f'Проверка фильтрации на 10.10.0.0/23(с параметром), ожидаемый результат: {str(self.gres_with_p)}')
        self.assertEqual(self.gres_with_p, list(net_filter(self.gres_with_p, self.n_deny, True)))
        self.print_pass('..OK')


if __name__ == '__main__':
    unittest.main()