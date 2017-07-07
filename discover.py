import logging
import time
import shutil
import subprocess
from threading import Thread
from datetime import datetime

from zeroconf import ServiceBrowser, Zeroconf, ServiceInfo
import netifaces
from flask import Flask
from flask_jsontools import JsonSerializableBase, jsonapi
from waitress import serve

log = logging.getLogger('discovery')

SERVICE_TYPE = "_liquid._tcp.local."
HOST_ONLY_NETWORK_MASK = '255.255.255.255'

nodes = {}
zeroconf = {}

def start_dnsmasq():
    subprocess.call(["sudo", " supervisorctl", "start", "dnsmasq-dns"])

def stop_dnsmasq():
    subprocess.call(["sudo", "supervisorctl", "stop", "dnsmasq-dns"])

def restart_dnsmasq():
    subprocess.call(["sudo", "supervisorctl", "restart", "dnsmasq-dns"])

def rewrite_dnsmasq_conf(path, conf_string):
    temp = path + ".tmp"
    with open(temp, 'w') as f:
        f.write(conf_string)
    shutil.move(temp, path)

class DnsmasqRestarter(Thread):
    def __init__(self):
        super().__init__()
        self.last_dnsmasq_command = ''

    def run(self):
        while True:
            self.update_dnsmasq()
            time.sleep(3)

    def update_dnsmasq(self):
        interface = app.config['DNS_INTERFACE']
        if not interface:
            if self.last_dnsmasq_command:
                stop_dnsmasq()
                self.last_dnsmasq_command = ''
            return

        command = get_dns_conf_string(interface)
        if command == self.last_dnsmasq_command:
            return

        rewrite_dnsmasq_conf(app.config['DNS_CONF_FILE'], command)
        if self.last_dnsmasq_command:
            restart_dnsmasq()
        else:
            start_dnsmasq()
        self.last_dnsmasq_command = command


def get_dns_conf_string(interface):
    ip = get_ipv4_addr(interface)
    common_args = [
        'domain-needed',
        'bogus-priv',
        'server=208.67.222.222',
        'server=208.67.220.220',
        'no-resolv',
        'no-hosts',
        'bind-interfaces',
    ]
    listen_args = [
        'interface={}'.format(interface),
        'listen-address={}'.format(ip),
    ]

    address_records = [
        (node['hostname'], node['address'])
        for node in nodes.get(interface, [])
        if not node['is_local']
    ]
    address_records.sort()
    address_records.insert(0, (app.config['LIQUID_DOMAIN'], ip))
    address_args = [
        'address=/{}/{}'.format(*record)
        for record in address_records
    ]

    args = common_args + listen_args + address_args
    return "\n".join(args) + "\n"

def dict_decode(data):
    def decode(data):
        if isinstance(data, bytes):
            return data.decode("latin-1")
        elif isinstance(data, str):
            return data
        return str(data)

    return {
        decode(key): decode(data[key])
        for key in data
    }

def get_ipv4_addr(interface):
    addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
    if not addrs:
        return None

    ips = [
        a['addr']
        for a in addrs
        if 'addr' in a
        and a.get('netmask') != HOST_ONLY_NETWORK_MASK
    ]

    if ips:
        assert len(ips) == 1, "Only one ip per interface is supported."
        return ips[0]
    else:
        return None

def get_data_from_info(interface, info, properties):
    hostname = properties['liquid_hostname']
    is_local = hostname == app.config['LIQUID_DOMAIN']
    if is_local:
        address = get_ipv4_addr(interface)
    else:
        address = ".".join(str(x) for x in info.address)

    return {
        "type": info.type,
        "server": info.server,
        "hostname": hostname,
        "is_local": is_local,
        "name": info.name,
        "address": address,
        "name": info.name,
        "port": info.port,
        "properties": properties,
        "discovered_at": datetime.now().isoformat()
    }

def add_record(name, interface, data):
    nodes.setdefault(interface, {})
    nodes[interface][name] = data

def remove_record(name, interface):
    del nodes[interface][name]

class WorkstationListener(object):
    def __init__(self, interface):
        self.interface = interface

    def add_service(self, zeroconf, type_, name):
        log.debug("+ %s add_service of type %s and name %s", self.interface, type_, name)
        info = zeroconf.get_service_info(type_, name, 10000)
        if not info:
            log.debug("+ % add_service info timed out on type %s and name %s", self.interface, type_, name)
            return
        properties = dict_decode(info.properties)
        if 'liquid_hostname' in properties:
            data = get_data_from_info(self.interface, info, properties)
            add_record(name, self.interface, data)

    def remove_service(self, zeroconf, type_, name):
        log.debug("- %s remove_service of type %s and name %s", self.interface, type_, name)
        if name in nodes:
            remove_record(name, self.interface)

def refresh_listeners():
    interfaces = netifaces.interfaces()
    log.debug("Initial list of interfaces: %r", interfaces)

    # start DNS and a listener for each interface
    for interface in interfaces:
        # find ipv4 address for interface
        ip = get_ipv4_addr(interface)
        if not ip:
            log.debug("Interface %s was skipped because it didn't have an IPv4 address", interface)
            continue
        if ip in ['127.0.0.1', '0.0.0.0']:
            log.debug("Interface %s was skipped because it had a blacklisted IPv4 address", interface)
            continue

        # start zeroconf service browser restricted to the interface's address
        log.info("Starting Zeroconf listener on %s, ip = %s", interface, ip)
        zeroconf[interface] = Zeroconf([ip])
        listener = WorkstationListener(interface)
        browser = ServiceBrowser(zeroconf[interface], SERVICE_TYPE, listener)
    if zeroconf.keys():
        log.info("Discovery running on interfaces: %s", ", ".join(zeroconf.keys()))
    else:
        log.info("Discovery not running on any interface.")

app = Flask(__name__)
app.config.from_pyfile('settings/common.py')
app.config.from_pyfile('settings/local.py', silent=True)

@app.route('/json')
@jsonapi
def list_workstations():
    return nodes

def main():
    logging.basicConfig(level=logging.DEBUG)
    refresh_listeners()
    dnsmasq_restarter = DnsmasqRestarter()
    dnsmasq_restarter.start()
    serve(app, host='127.0.0.1', port=13777)

if __name__ == "__main__":
    main()
