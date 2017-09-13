import logging
LOG_LEVEL = logging.DEBUG

# FQDN for current machine
LIQUID_DOMAIN = "example.liquid"

# DNS interface that the DNS server runs on
DNSMASQ_INTERFACE = None

# Default location of dns conf file to be generated
DNSMASQ_CONFIG_FILE = "/var/lib/liquid/conf/discover/dnsmasq.conf"

# Default HTTP port
HTTP_PORT = '13777'

# Default DNS upstream servers (OpenDNS ips)
DNS_SERVERS = ['208.67.222.222', '208.67.220.220']
