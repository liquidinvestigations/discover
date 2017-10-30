import re
import logging
from datetime import datetime

from zeroconf import ServiceBrowser, Zeroconf
import netifaces
import flask

class ValidationError(RuntimeError):
    pass


SERVICE_TYPE = "_liquid._tcp.local."
log = logging.getLogger('discovery')
nodes = {}


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


def normalize_dict_str(data):
    return {
        str(key, encoding='latin-1'): str(data[key], encoding='latin-1')
        for key in data
    }


def get_ipv4_addr(interface):
    def valid_addr(a):
        return 'addr' in a

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
    def make_list(nodes):
        node_list = []
        hostname_added = {}
        for interface in nodes:
            for name in nodes[interface]:
                node = nodes[interface][name]
                if not node['is_local']:
                    if hostname_added.get(node['hostname']):
                        continue
                    else:
                        hostname_added[node['hostname']] = True
                    node_list.append({
                        'hostname': node['hostname'],
                        'data': {
                            'discovery_interface': interface,
                            'discovered_at': node['discovered_at'],
                            'address': node['address'],
                            'last_seen_at': datetime.utcnow().isoformat(),
                        }
                    })
        return node_list
    return flask.jsonify(make_list(nodes.copy()))


@app.route('/')
def status():
    return flask.jsonify({
        'status': 'ok',
    })


def main():
    import waitress

    log.setLevel(app.config['LOG_LEVEL'])
    refresh_listeners()
    waitress.serve(app, host='127.0.0.1', port=app.config['HTTP_PORT'])


if __name__ == "__main__":
    main()
