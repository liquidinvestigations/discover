import http.client
import socket
import xmlrpc.client

# This is a Python 3 implementation of using the XML-RPC interface
# communicate with a supervisor server.

class UnixStreamHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.host)

class UnixStreamTransport(xmlrpc.client.Transport, object):
    def __init__(self, socket_path):
        self.socket_path = socket_path
        super(UnixStreamTransport, self).__init__()

    def make_connection(self, host):
        return UnixStreamHTTPConnection(self.socket_path)

def connect_unix_socket(socket_path='/var/run/supervisor.sock'):
    transport = UnixStreamTransport(socket_path)
    # xmlrpc.client requires a URL starting with 'http' or 'https'
    url = 'http://argument_unused'
    return xmlrpc.client.ServerProxy(url, transport=transport)

def connect_http(url):
    return xmlrpc.client.ServerProxy(url)
