#!/usr/bin/python3

import nmap
import os

def welcome():
    welc = 'NMAP Network Status by F1neg4n'
    os.system('clear')
    print(welc + '\n' + '*' * len(welc))
    return

def networkStatus():
    welcome()
    print('[+] Scanning network...\n')
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    print('Host\t\t   Status')
    print('----\t\t   ------')
    for host, status in hosts_list:
        print(host + '\t : ' + status)
    return

if __name__ == '__main__':
    networkStatus()
