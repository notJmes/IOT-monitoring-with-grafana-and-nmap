import re
from datetime import datetime

def scrape(text):

    r = re.compile(r'((?<=Nmap scan report for )(?P<device_name>.*)\s\((?P<ip_addr>\d*\.\d*\.\d*\.\d*)\)|(?<=Nmap scan report for )(?P<ip_addr2>\d*\.\d*\.\d*\.\d*))\nHost is up \((?P<latency>.*)s.*\nMAC Address:\s(?P<mac_addr>([A-z0-9]{2}:){5}[A-z0-9]{2})\s\((?P<nic_name>.*)\)\n')
    devices = [m.groupdict() for m in r.finditer(text)]
    for i, v in enumerate(devices):
        if v['ip_addr'] is None:
            v['ip_addr'] = v['ip_addr2']
            del v['ip_addr2']
        else:
            del v['ip_addr2']
        devices[i] = v
    # [print(item) for item in devices]

    r = re.compile(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}')
    ts = datetime.strptime(r.search(text).group(), '%Y-%m-%d %H:%M')


    return devices, ts


# ((?<=Nmap scan report for )(.*)\s\((\d*\.\d*\.\d*\.\d*)\)|(?<=Nmap scan report for )(\d*\.\d*\.\d*\.\d*))\nHost is up \((.*)s.*\nMAC Address:\s(.*)\s\((.*)\n

if __name__ == '__main__':
    log = open('scan.txt').read()

    connections, d = scrape(log)
    print(connections, d)