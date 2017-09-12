import re
import logging
import time
import shutil
from threading import Thread
from datetime import datetime

from zeroconf import ServiceBrowser, Zeroconf
import netifaces
import flask

import supervisor_client

class ValidationError(RuntimeError):
    pass


log = logging.getLogger('discovery')

SERVICE_TYPE = "_liquid._tcp.local."
DNSMASQ_PROCESS_NAME = 'dnsmasq-dns'

nodes = {}

def reload_dnsmasq():
    log.debug("Reloading dnsmasq-dns")
    supervisor = supervisor_client.connect()
    dnsmasq_process_info = supervisor.getProcessInfo(DNSMASQ_PROCESS_NAME)
    if dnsmasq_process_info['statename'] == 'RUNNING':
        supervisor.stopProcess(DNSMASQ_PROCESS_NAME)
    supervisor.startProcess(DNSMASQ_PROCESS_NAME)

def stop_dnsmasq():
    log.debug("Stopping dnsmasq-dns")
    supervisor = supervisor_client.connect()
    supervisor.stopProcess(DNSMASQ_PROCESS_NAME)

def rewrite_dnsmasq_conf(path, conf_string):
    temp = path + ".tmp"
    with open(temp, 'w') as f:
        f.write(conf_string)
    shutil.move(temp, path)

def manage_dnsmasq():
    def update_dnsmasq():
        nonlocal last_dnsmasq_conf_string
        interface = app.config['DNSMASQ_INTERFACE']

        conf_string = get_dns_conf_string(interface)
        if conf_string == last_dnsmasq_conf_string:
            return

        rewrite_dnsmasq_conf(app.config['DNSMASQ_CONFIG_FILE'], conf_string)
        last_dnsmasq_conf_string = conf_string
        reload_dnsmasq()

    last_dnsmasq_conf_string = ''
    while True:
        update_dnsmasq()
        time.sleep(3)

def validate_hostname(hostname):
    if not bool(re.match(r"^((\w|-)+\.)+(\w+)$", hostname)):
        raise ValidationError("invalid hostname: {}".format(hostname))

def validate_ipv4_address(address):
    if not bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", address)):
        raise ValidationError("invalid ipv4 address: {}".format(address))

def valid_record(interface, hostname, address):
    try:
        validate_hostname(hostname)
        validate_ipv4_address(address)
    except ValidationError:
        log.warning("%r skipping record with hostname %r and address %r",
                    interface, hostname, address)
        return False
    else:
        return True

def get_dns_conf_string(interface):
    ip = get_ipv4_addr(interface)
    common_args = [
        'domain-needed',
        'bogus-priv',
        'no-resolv',
        'no-hosts',
        'bind-interfaces',
        'interface={}'.format(interface),
        'listen-address={}'.format(ip),
        'interface=lo',
        'listen-address=127.0.0.1',
    ]

    dns_servers = [
        'server=' + dns_server_ip
        for dns_server_ip in app.config["DNS_SERVERS"]
    ]

    address_records = [
        (node['hostname'], node['address'])
        for node in nodes.get(interface, {}).values()
        if not node['is_local']
    ]
    address_records.sort()

    # add current node as first dns record
    address_records.insert(0, (app.config['LIQUID_DOMAIN'], ip))
    address_args = [
        'address=/{}/{}'.format(hostname, address)
        for hostname, address in address_records
        if valid_record(interface, hostname, address)
    ]

    args = common_args + dns_servers + address_args
    return "\n".join(args) + "\n"

def normalize_dict_str(data):
    return {
        str(key, encoding='latin-1'): str(data[key], encoding='latin-1')
        for key in data
    }

def get_ipv4_addr(interface):
    def valid_addr(a):
        return 'addr' in a and \
               validate_ipv4_address(a['addr'])

    addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
    if not addrs:
        return None

    ips = [
        a['addr']
        for a in addrs
        if valid_addr(a)
    ]

    if ips:
        assert len(ips) == 1, "Only one ip per interface is supported."
        return ips[0]
    else:
        return None

def handle_new_service(name, interface, service_info):
    properties = normalize_dict_str(service_info.properties)
    hostname = properties.get('liquid_hostname')
    if not hostname:
        return
    is_local = (hostname == app.config['LIQUID_DOMAIN'])
    if is_local:
        address = get_ipv4_addr(interface)
    else:
        address = "{}.{}.{}.{}".format(*service_info.address)

    data = {
        "hostname": hostname,
        "is_local": is_local,
        "address": address,
        "discovered_at": datetime.utcnow().isoformat()
    }
    add_record(name, interface, data)

def add_record(name, interface, data):
    nodes.setdefault(interface, {})
    nodes[interface][name] = data

def remove_record(name, interface):
    del nodes[interface][name]

class LiquidServiceListener(object):
    def __init__(self, interface):
        self.interface = interface

    def add_service(self, zeroconf, type_, name):
        log.debug("+ %r add_service of type %r and name %r",
                  self.interface, type_, name)
        info = zeroconf.get_service_info(type_, name, 10000)
        if not info:
            log.debug("+ %r add_service info timed out on type %r and name %r",
                      self.interface, type_, name)
            return
        handle_new_service(name, self.interface, info)

    def remove_service(self, zeroconf, type_, name):
        log.debug("- %r remove_service of type %r and name %r",
                  self.interface, type_, name)
        if self.interface in nodes:
            if name in nodes[self.interface]:
                remove_record(name, self.interface)

def refresh_listeners():
    interfaces = netifaces.interfaces()
    log.debug("Initial list of interfaces: %r", interfaces)

    # start DNS and a listener for each interface
    for interface in interfaces:
        # find ipv4 address for interface
        ip = get_ipv4_addr(interface)
        if not ip:
            log.debug(("Interface %r was skipped because" +
                       "it didn't have an IPv4 address"),
                      interface)
            continue
        if ip in ['0.0.0.0']:
            log.debug(("Interface %r was skipped because" +
                       "it had a unsupported IPv4 address"),
                      interface)
            continue

        # start zeroconf service browser restricted to the interface's address
        log.info("Starting Zeroconf listener on %r, ip = %r", interface, ip)
        zeroconf = Zeroconf([ip])
        listener = LiquidServiceListener(interface)
        ServiceBrowser(zeroconf, SERVICE_TYPE, listener)


app = flask.Flask(__name__)
app.config.from_pyfile('settings/common.py')
app.config.from_pyfile('settings/local.py', silent=True)
app.config.from_pyfile('settings/secret_key.py', silent=True)

@app.route('/nodes')
def list_nodes():
    return flask.jsonify(nodes)

@app.route('/')
def status():
    supervisor = supervisor_client.connect()
    supervisor_info = {
        'status': supervisor.getState()['statename'],
        'version': supervisor.getVersion(),
    }
    supervisor_dns_info = supervisor.getProcessInfo(DNSMASQ_PROCESS_NAME)
    dns_info = {
        key: supervisor_dns_info[key]
        for key in ['statename', 'description']
    }

    return flask.jsonify({
        'status': 'ok',
        'supervisor': supervisor_info,
        'dns': dns_info,
        'dns_interface': app.config['DNSMASQ_INTERFACE'],
    })

def main():
    import waitress

    log.setLevel(app.config['LOG_LEVEL'])
    refresh_listeners()
    Thread(target=manage_dnsmasq).start()
    waitress.serve(app, host='127.0.0.1', port=app.config['HTTP_PORT'])


if __name__ == "__main__":
    main()
