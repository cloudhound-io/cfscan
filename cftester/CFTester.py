import requests
from requests.auth import HTTPBasicAuth
import urlparse
from .Tester import Tester, test

join = urlparse.urljoin
requests.packages.urllib3.disable_warnings()

class CFTester(Tester):

    def __init__(self, *args, **kwargs):
        super(CFTester, self).__init__(*args, **kwargs)
        self.info = requests.get(join(self.target, '/v2/info'), verify=False).json()

    @test
    def well_known_uaa_keys(self):

        """ well-known UAA cryptographic keys """

        github_uaa_manifest = requests.get(
            'https://raw.githubusercontent.com/cloudfoundry/uaa/master/uaa/src/main/resources/uaa.yml',
            verify=False
        ).text

        token_endpoint = self.info.get('token_endpoint')
        if not token_endpoint:
            self.format(self.stderr, 'cannot extract token_endpoint')
            yield False, 'cannot extract token_endpoint from info hash'
            return

        token_keys = requests.get(join(token_endpoint, '/token_keys'), verify=False)
        if not token_keys.status_code == 200:
            yield False, 'cannot reach ' + join(token_endpoint, '/token_keys')
            return

        token_keys = token_keys.json().get('keys')

        for token_key in token_keys:
            first_line = token_key.get('value').split('\n')[1]
            if first_line in github_uaa_manifest:
                yield False, 'key "%s..." is a default token signing key and should be changed immediately' % first_line
            else:
                yield True, 'key "%s..." is not a default token signing key' % first_line


    @test
    def cc_version(self):

        """ Cloud Controller version """

        latest_version = requests.get(
            'https://raw.githubusercontent.com/cloudfoundry/cloud_controller_ng/master/config/version_v2',
            verify=False
        ).text

        latest_major, latest_minor = map(int, latest_version.split('.')[0:2])
        major, minor = map(int, self.info.get('api_version', '2.0.0').split('.')[0:2])

        if major < latest_major or minor < latest_minor:
            yield False, 'cloud controller is at version %d.%d, latest version is %d.%d' % \
                  (major, minor, latest_major, latest_minor)
        else:
            yield True, 'cloud controller is at latest version ' + latest_version

        if major <= 2:
            if minor <= 75:
                yield False, 'cloud controller vulnerable to CVE-2017-8048, which allows complete CF takeover via remote code execution and should be updated'
            if minor <= 70:
                yield False, 'cloud controller vulnerable to CVE-2017-8037, which allows complete CF takeover via any file download and should be updated'
            if minor <= 68:
                yield False, 'cloud controller vulnerable to CVE-2017-8033, which allows complete CF takeover via remote code execution and should be updated'
                if minor >= 44:
                    yield False, 'cloud controller vulnerable to CVE-2017-8035, which allows complete CF takeover via any file download and should be updated'


    @test
    def well_known_credentials(self):

        """ UAA well-known credentials """

        well_knwon_creds = [
            ('cc_routing', 'cc-routing-secret'),
            ('cloud_controller_username_lookup', 'cloud-controller-username-lookup-secret'),
            ('doppler', 'loggregator-secret'),
            ('gorouter', 'gorouter-secret'),
            ('login', 'login-secret'),
            ('network-policy', 'network-policy-secret'),
            ('spring_cloud_broker', 'spring-cloud-broker-secret'),
            ('tcp_emitter', 'tcp-emitter-secret'),
            ('admin', 'admin-client-secret'),
            ('tcp_router', 'tcp-router-secret'),
            ('cc-service-dashboards', 'cc-broker-secret')
        ]

        token_endpoint = self.info.get('token_endpoint')
        if not token_endpoint:
            self.format(self.stderr, 'cannot extract token_endpoint')
            yield False, 'cannot extract token_endpoint from info hash'
            return

        token_endpoint = join(token_endpoint, '/oauth/token')

        for creds in well_knwon_creds:

            attempt = requests.get(
                token_endpoint,
                params={"grant_type":"client_credentials"},
                auth=HTTPBasicAuth(*creds),
                verify=False
            )

            if attempt.status_code == 200:
                yield False, 'UAA is using well-known credential "%s:%s", this must be changed immediately' % creds
            else:
                yield True, 'UAA does not use well-known credentials "%s:%s"' % creds


    @test
    def default_app_ssh_host_key_fingerprint(self):

        """ default app SSH host key """

        default_key = 'a6:d1:08:0b:b0:cb:9b:5f:c4:ba:44:2a:97:26:19:8a'

        if self.info.get('app_ssh_host_key_fingerprint').lower() == default_key:
            yield False, 'app SSH is using the default SSH host key "%s", should be changed immediately' % default_key
            return
        yield True, 'app SSH is using a non-default SSH Host key "%s"' % self.info.get('app_ssh_host_key_fingerprint')


    @test
    def insecure_protocols(self):

        """ insecure communication protocols """

        http_urls = [ self.target, self.info.get('token_endpoint'), self.info.get('authorization_endpoint') ]
        ws_urls = [ self.info.get('logging_endpoint'), self.info.get('doppler_logging_endpoint')]

        for url in http_urls:

            if not url:
                continue

            insecure = urlparse.urlparse(url)
            insecure_url = urlparse.urlunparse(('http', insecure.hostname, '/', None, None, None))

            try:
                attempt = requests.get(insecure_url, allow_redirects=False)
                if attempt.status_code == 200:
                    yield False, 'endpoint "%s" accessible over insecure http://, should only be https://' % insecure.hostname
                if attempt.status_code >= 300 and attempt.status_code < 400:
                    yield False, 'endpoint "%s" accessible over insecure http://, ' \
                                 'but automatically attempts redirect to https://, ' \
                                 'could lead to man-in-the-middle attacks' % insecure.hostname
            except:
                yield True, 'endpoint "%s" not accessible over http://' % insecure.hostname


        for url in ws_urls:

            if not url:
                continue

            insecure = urlparse.urlparse(url)
            insecure_url = urlparse.urlunparse(('ws', insecure.hostname, '/', None, None, None))


            try:
                attempt = requests.get(insecure_url, allow_redirects=False)
                if attempt.status_code == 200:
                    yield False, 'endpoint "%s" accessible over insecure ws://, should only be wss://' % insecure.hostname
                if attempt.status_code >= 300 and attempt.status_code < 400:
                    yield False, 'endpoint "%s" accessible over insecure ws://, ' \
                                 'but automatically attempts redirect to wss://, ' \
                                 'this could lead to man-in-the-middle attacks' % insecure.hostname
            except:
                yield True, 'endpoint "%s" not accessible over ws://' % insecure.hostname
