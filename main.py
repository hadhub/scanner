#!/usr/bin/python3
import argparse
import nmap

def main():
    Parser = argparse.ArgumentParser()
    Parser.add_argument('-t','--target',help="Specify the target", required=True)
    Args = Parser.parse_args()
    TARGET = Args.target
    nmapScan(TARGET)
    

def nmapScan(TARGET):
    DefaultScanner = nmap.PortScanner()
    print(f'[i] Scanning... {TARGET}')
    DefaultScanner.scan(hosts=TARGET, arguments=f'-T4 -p- -Pn -n -oN {TARGET}_default-scan.txt')
    for proto in DefaultScanner[TARGET].all_protocols():
        print(f'[+] {proto}\n')

    ports = list(DefaultScanner[TARGET][proto].keys())

    for port in ports:
        print(f'Port : {port}/{proto} : '+ DefaultScanner[TARGET][proto][port]['name'])

    print()
    print(f"Default scan done ! Check {TARGET}_default-scan.txt")
    print('Service Scan starting...')

    ports = ''.join(str(x)+',' for x in ports)[:-1]

    DefaultScanner.scan(hosts=TARGET, arguments=f'-sC -sV -T4 -Pn -n -p{ports} -oN {TARGET}_services-scan.txt')
    print(f"Service scan done ! Check {TARGET}_services-scan.txt")
if __name__ == '__main__':
    main()
