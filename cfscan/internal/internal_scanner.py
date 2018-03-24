import BaseHTTPServer
import socket
import struct
import os
import thread
import json
import urllib2
import base64
import ssl
import uuid
import urlparse
import multiprocessing

PASS = True
FAIL = False
CRLF = '\r\n'

DEFAULT_INSTANCE_IP = '10.0.0.0'
DEFAULT_SUBNET_MASK = '255.255.0.0'
DEFAULT_NPROCS      = 32
DEFAULT_NHOSTS      = 65536
DEFAULT_TIMEOUT_SEC = 0.05  # 50 milliseconds

# redefine scanner.py, because we don't want any external dependencies here:

def test(func):
    """
    :type func function
    mark function as test
    """
    func.__test__ = True
    func.desc = func.__doc__.strip()
    func.name = func.__name__
    return func


class Scanner(object):

    def get_tests(self):
        return [o for o in self.__class__.__dict__.itervalues() if (callable(o) and hasattr(o, '__test__'))]

    def scan(self):
        for testfunc in self.get_tests():
            try:
                result = testfunc(self)
                yield testfunc, result
            except BaseException as e:
                yield testfunc, [(FAIL, e.message)]


# define some inet4 methods:

def unpack_inet4(packed):
    packed = socket.inet_aton(packed)
    return struct.unpack('>I', packed)[0]


def pack_inet4(unpacked):
    return socket.inet_ntoa(struct.pack('>I', unpacked))


# internal discovery function, this has to be in global scope because multiprocessing won't pickle it correctly:

NET = unpack_inet4(os.getenv('CF_INSTANCE_IP', DEFAULT_INSTANCE_IP)) & unpack_inet4(DEFAULT_SUBNET_MASK)

def discover_one(host):

    import socket

    out = []
    well_known_ports = [
        ('ETCD', 4001),
        ('ETCD-CLUSTER', 7001),
        ('NATS', 4222),
        ('MYSQL', 3306),
        ('GOROUTER', 8087),
        ('REP', 1801),
        ('AUCTIONEER', 9016),
        ('STAGER', 8890),
        ('BBS', 8889),
        ('NSYNC', 8787),
        ('TPS', 1518),
        ('CC-UPLOADER', 9090),
        ('DOPPLER', 8082)
    ]

    if not isinstance(host, basestring):
        host = pack_inet4(NET + host)

    for name, port in well_known_ports:
        sock = socket.socket()
        sock.settimeout(DEFAULT_TIMEOUT_SEC)
        try:
            sock.connect((host, port))
            out.append((name, host, port))
        except:
            pass
        finally:
            sock.close()

    return out


class InternalScanner(Scanner):

    def __init__(self):
        super(InternalScanner, self).__init__()

        self.components         = {}
        self.__discover         = discover_one
        self.discovering        = False
        self.discovery_part     = 0
        self.discovery_whole    = DEFAULT_NHOSTS
        self.pool               = multiprocessing.Pool(DEFAULT_NPROCS)

        thread.start_new(self.discover, ())

    def discover(self):

        if self.discovering:
            return

        self.discovering = True

        for result in self.pool.imap_unordered(self.__discover, xrange(self.discovery_whole)):
            self.discovery_part += 1
            for name, host, port in result:
                components = self.components.get(name, [])
                components.append((host, port))
                self.components.update({name: components})

        self.discovering = False


    def well_known_go_router_credentials(self):

        well_known_creds = [
            ('varz', 'varzsecret'),
            ('healthz', 'healthzsecret')
        ]

        if len(self.components.get('GOROUTER', [])) == 0:
            yield PASS, 'gorouter status not accessible / discoverable from application network'
            return

        for host, port in self.components.get('GOROUTER', []):
            fail = False
            for user, password in well_known_creds:
                req = urllib2.Request('http://%s:%d/varz' % (host, port))
                req.add_header('Authorization', 'Basic ' + base64.b64encode('%s:%s' % (user, password)))
                try:
                    res = urllib2.urlopen(req)
                    if res.code == 200:
                        fail = True
                        yield FAIL, 'gorouter host %s uses well-known status credential "%s:%s"' % \
                              (host, user, password)
                        break
                except:
                    pass

            if not fail:
                yield PASS, 'gorouter host %s does not use well-known status credentials'

    def well_known_nats_credentials(self):

        well_known_creds = [
            ('nats', 'nats'),
            ('derek', 'T0pS3cr3t'),
        ]

        if len(self.components.get('NATS', [])) == 0:
            yield PASS, 'nats hosts not accessible / discoverable from application network'
            return

        for host in self.components.get('NATS', []):
            fail = False
            sock = socket.socket()
            sock.connect(host)
            info = sock.recv(65535)
            info = json.loads(info[5:]) # structure of NATS info message is "INFO {/JSON/}"
            sock.close()
            if not info.get('auth_required', False):
                fail = True
                yield FAIL, 'nats host %s does not require authentication' % host[0]
                continue

            for user, password in well_known_creds:
                sock = socket.socket()
                sock.connect(host)
                sock.recv(65535) # we don't care about the info message anymore
                msg = json.dumps({
                    'user': user,
                    'pass': password,
                    'version': info.get('version'),
                    'lang': 'go',
                    'verbose': True
                })
                sock.send('CONNECT ' + msg + CRLF)
                response = sock.recv(65535)
                sock.close()
                if '+OK' in response:
                    fail = True
                    yield FAIL, 'nats host %s uses well-known credential "%s:%s"' % (host[0], user, password)
                    break

            if not fail:
                yield PASS, 'nats host %s does not use well-known credentials' % host[0]

    @test
    def well_known_credentials(self):

        """ Well-known credentials used in internal Cloud Foundry components """

        for status, msg in self.well_known_nats_credentials():
            yield status, msg

        for status, msg in self.well_known_go_router_credentials():
            yield status, msg

    def anonymous_access_to(self, component, scheme='http', path='/', method='GET', response_code=200):

        if len(self.components.get(component, [])) == 0:
            yield PASS, 'no %s hosts accessible / discoverable from application network' % component
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for host, port in self.components.get(component):
            req = urllib2.Request('%s://%s:%d%s' % (scheme, host, port, path))
            req.get_method = lambda: method.upper()
            code = 0
            try:
                res = urllib2.urlopen(req, context=ctx)
                code = res.code
            except urllib2.HTTPError as e:
                code = e.code

            if code == response_code:
                yield FAIL, '%s host %s accessible anonymously from application network' % (component, host)
            else:
                yield FAIL, '%s host %s accessible from application network but not anonymously' % (component, host)

    @test
    def anonymous_access_from_app_network(self):

        """ Anonymous access to internal Cloud Foundry components from application network """

        for status, msg in self.anonymous_access_to('REP', path='/state'):
            yield status, msg

        for status, msg in self.anonymous_access_to('AUCTIONEER', path='/v1/lrps', method='POST', response_code=400):
            yield status, msg

        for status, msg in self.anonymous_access_to('BBS', path='/v1/ping', method='POST'):
            yield status, msg

        for status, msg in self.anonymous_access_to('STAGER', path='/v1/staging/' + str(uuid.uuid4()), response_code=404):
            yield status, msg

        for status, msg in self.anonymous_access_to('NSYNC', path='/v1/tasks', method='POST', response_code=400):
            yield status, msg

        for status, msg in self.anonymous_access_to('TPS', path='/v1/bulk_actual_lrp_status', response_code=400):
            yield status, msg

        for status, msg in self.anonymous_access_to('ETCD', path='/v2/keys'):
            yield status, msg
            
        for status, msg in self.anonymous_access_to('ETCD-CLUSTER', path='/v2/members'):
            yield status, msg


__internal_scanner_instance = None


def get_internal_scanner():
    global __internal_scanner_instance
    if __internal_scanner_instance:
        return __internal_scanner_instance
    __internal_scanner_instance = InternalScanner()
    return __internal_scanner_instance


class InternalScannerApplication(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_GET(self):
        scanner = get_internal_scanner()  # type: InternalScanner

        if self.path == '/discovery_status':
            status = json.dumps({'whole': scanner.discovery_part, 'part': scanner.discovery_whole})
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(status)))
            self.end_headers()
            self.wfile.write(status)

        elif self.path == '/components':
            status = json.dumps(scanner.components)
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(status)))
            self.end_headers()
            self.wfile.write(status)

        elif self.path.startswith('/discover?host='):
            query = urlparse.urlparse(self.path).query
            if not query:
                self.send_error(400, 'MISSING QUERY PARAM')
                self.end_headers()
            else:
                query = dict(qc.split("=") for qc in query.split("&"))
                if not query or not query.get('host'):
                    self.send_error(400, 'MISSING QUERY PARAM')
                    self.end_headers()
                else:
                    data = discover_one(query.get('host'))
                    for name, host, port in data:
                        components = scanner.components.get(name, [])
                        components.append((host, port))
                        scanner.components.update({name: components})
                    status = json.dumps(data)
                    self.send_response(200)
                    self.send_header('content-type', 'application/json')
                    self.send_header('content-length', str(len(status)))
                    self.end_headers()
                    self.wfile.write(status)

        elif self.path == '/scan':

            def write_chunk(chunk):
                tosend = '%X\r\n%s\r\n'
                self.wfile.write(tosend % (len(chunk), chunk))

            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('transfer-encoding', 'chunked')
            self.end_headers()

            for test, result in scanner.scan():
                for status, msg in result:
                    write_chunk(json.dumps({
                        "name": test.name,
                        "description": test.desc,
                        "status": status,
                        "msg": msg
                    }))

            # send trailer:
            write_chunk('')
        
        else:
            
            status = json.dumps({'error': 'not found %s' % self.path})
            self.send_response(404)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(status)))
            self.end_headers()
            
            self.wfile.write(status)
                         

if __name__ == '__main__':
    BaseHTTPServer.HTTPServer(('', int(os.getenv('PORT', '9090'))), InternalScannerApplication).serve_forever()
