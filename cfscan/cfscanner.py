import requests
from requests.auth import HTTPBasicAuth
import urlparse
from .scanner import Scanner, test, PASS, FAIL

# set up some utilities:
join = urlparse.urljoin


def parse_version(version_string):
    return map(int, version_string.split('.')[0:2])


# disable requests SSL verification:
original_requests_get = requests.get


def insecure_requests_get(*args, **kwargs):
    kwargs.update({'verify': False})
    return original_requests_get(*args, **kwargs)


requests.get = insecure_requests_get

# disable urllib3 from complaining about SSL verification:
requests.packages.urllib3.disable_warnings()


class CFScanner(Scanner):

    def __init__(self, *args, **kwargs):
        super(CFScanner, self).__init__(*args, **kwargs)
        self.info = requests.get(join(self.target, '/v2/info')).json()

    @test
    def well_known_uaa_keys(self):

        """ Well-known cryptographic keys """

        manifests = [
            'https://raw.githubusercontent.com/cloudfoundry/uaa/master/uaa/src/main/resources/uaa.yml',
            'https://raw.githubusercontent.com/cloudfoundry/cloud_controller_ng/master/config/bosh-lite.yml',
            'https://raw.githubusercontent.com/cloudfoundry/cloud_controller_ng/master/config/cloud_controller.yml'
        ]

        manifest_data = '\n'.join(map(lambda x: requests.get(x).text, manifests))

        token_endpoint = self.info.get('token_endpoint')
        if not token_endpoint:
            self.format(self.stderr, 'cannot extract token_endpoint')
            yield FAIL, 'cannot extract token_endpoint from info hash'
            return

        token_keys = requests.get(join(token_endpoint, '/token_keys'))
        if not token_keys.status_code == 200:
            yield FAIL, 'cannot reach ' + join(token_endpoint, '/token_keys')
            return

        token_keys = token_keys.json().get('keys')

        for token_key in token_keys:
            first_line = token_key.get('value').split('\n')[1]
            if first_line in manifest_data:
                yield FAIL, 'key "%s..." is a default token signing key and should be changed immediately' % first_line
            else:
                yield PASS, 'key "%s..." is not a default token signing key' % first_line

        app_ssh_key = self.info.get('app_ssh_host_key_fingerprint')
        if app_ssh_key:
            if app_ssh_key in manifest_data:
                yield FAIL, 'app SSH is using the default SSH host key "%s", should be changed immediately' % app_ssh_key
            else:
                yield PASS, 'app SSH is using a non-default SSH Host key "%s"' % app_ssh_key


    @test
    def uaa_version(self):

        """ Platform UAA version """

        latest_version = requests.get(
            "https://raw.githubusercontent.com/cloudfoundry/uaa/master/gradle.properties",
        ).text.split('=')[-1]

        current_version = requests.get(
            join(self.info.get('token_endpoint'), '/login'),
            headers={'accept': 'application/json'}
        ).json()

        latest_major, latest_minor = parse_version(latest_version)
        major, minor = parse_version(current_version.get('app', {'version': '0.0.0'}).get('version'))

        if major < latest_major or minor < latest_minor:
            yield FAIL, 'UAA version is %d.%d, latest version is %d.%d' % (major, minor, latest_major, latest_minor)
        else:
            yield PASS, 'UAA is at latest version %s' % latest_version
            return


    @test
    def cf_version(self):

        """ Cloud Foundry version and known CVEs """

        latest_version = requests.get(
            'https://raw.githubusercontent.com/cloudfoundry/cloud_controller_ng/master/config/version_v2'
        ).text

        latest_major, latest_minor = parse_version(latest_version)
        major, minor = parse_version(self.info.get('api_version', '2.0.0'))

        if major < latest_major or minor < latest_minor:
            yield FAIL, 'cloud controller is at version %d.%d, latest version is %d.%d' % \
                  (major, minor, latest_major, latest_minor)
        else:
            yield PASS, 'cloud controller is at latest version ' + latest_version
            return

        if major <= 2:
            if minor <= 79:
                yield FAIL, 'uaa vulnerable to CVE-2017-8031, which allows for denial of service'
            if minor <= 75:
                yield FAIL, 'cloud controller vulnerable to CVE-2017-8048, which allows remote code execution on cloud controller host'
            if minor <= 70:
                yield FAIL, 'cloud controller vulnerable to CVE-2017-8037, which allows sensitive data access'
            if minor <= 68:
                yield FAIL, 'cloud controller vulnerable to CVE-2017-8033, which allows for remote code execution on cloud controller host'
                if minor >= 44:
                    yield FAIL, 'cloud controller vulnerable to CVE-2017-8035, which allows for sensitive data access'
            if minor <= 63:
                yield FAIL, 'uaa vulnerable to CVE-2017-4994, which allows for account takeover'
            if minor <= 60:
                yield FAIL, 'uaa vulnerable to CVE-2017-4991, which allows for account takeover'
            if minor <= 58:
                yield FAIL, 'uaa vulnerable to CVE-2017-4974, which allows for sensitive data access'
            if minor <= 52:
                yield FAIL, 'uaa vulnerable to CVE-2017-4963, which allow for account takeover if using external authentication (LDAP\SAML\etc.)'




    @test
    def well_known_credentials(self):

        """ Well-known credentials """

        uaa_well_knwon_creds = [
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
            yield FAIL, 'cannot extract token_endpoint from info hash'
            return

        token_endpoint = join(token_endpoint, '/oauth/token')

        fail = False

        for creds in uaa_well_knwon_creds:

            attempt = requests.get(
                token_endpoint,
                params={"grant_type":"client_credentials"},
                auth=HTTPBasicAuth(*creds)
            )

            if attempt.status_code == 200:
                yield FAIL, 'UAA is using well-known credential "%s:%s"' % creds
                fail = True

        if not fail:
            yield PASS, 'UAA does not use well-known credentials'

        cf_internal_api_creds = [
            ('internal_user', 'internal-password'),
            ('internal_user', 'internal-api-password'),
            ('bulk_api', 'bulk-api-password'),
            ('bulk_api', 'bulk-password')
        ]

        fail = False

        for creds in cf_internal_api_creds:
            attempt = requests.get(join(self.target, '/internal/buildpacks'), auth=HTTPBasicAuth(*creds))
            if attempt.status_code == 200:
                fail = True
                break

        if fail:
            yield FAIL, 'Cloud Controller using well-known credentials "%s:%s" for internal api' % creds
        else:
            yield PASS, 'Cloud Controller does not use well-known internal api credentials'


    @test
    def insecure_protocols(self):

        """ Insecure communication protocols """

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
                    yield FAIL, 'endpoint "%s" accessible over insecure http://, should only be https://' % insecure.hostname
                if attempt.status_code >= 300 and attempt.status_code < 400:
                    yield FAIL, 'endpoint "%s" accessible over insecure http://, ' \
                                 'but automatically redirects to https://, ' \
                                 'could lead to man-in-the-middle attacks' % insecure.hostname
            except:
                yield PASS, 'endpoint "%s" not accessible over http://' % insecure.hostname

        for url in ws_urls:

            if not url:
                continue

            insecure = urlparse.urlparse(url)
            insecure_url = urlparse.urlunparse(('http', insecure.hostname, '/', None, None, None))


            try:
                attempt = requests.get(insecure_url, allow_redirects=False)
                if attempt.status_code == 200 or attempt.status_code == 404:
                    yield FAIL, 'endpoint "%s" accessible over insecure ws://, should only be wss://' % insecure.hostname
                if attempt.status_code >= 300 and attempt.status_code < 400:
                    yield FAIL, 'endpoint "%s" accessible over insecure ws://, ' \
                                 'but automatically redirects to wss://, ' \
                                 'this could lead to man-in-the-middle attacks' % insecure.hostname
            except:
                yield PASS, 'endpoint "%s" not accessible over ws://' % insecure.hostname
