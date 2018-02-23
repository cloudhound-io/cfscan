import requests
from requests.auth import HTTPBasicAuth
import urlparse
from .scanner import Scanner, test, PASS, FAIL

# set up some utilities:
join = urlparse.urljoin


def parse_version(version_string):
    return map(int, version_string.split('.')[0:2])

# disable urllib3 from complaining about SSL verification:
requests.packages.urllib3.disable_warnings()


class CFScanner(Scanner):

    def __init__(self, target, skip_ssl_verify=False):
        super(CFScanner, self).__init__(target)
        self.info_endpoint = join(self.target, '/v2/info')
        self.ssl_verify = not skip_ssl_verify
        self.info = self.get(self.info_endpoint).json()
        assert self.info, self.info_endpoint + " did not return the expected CF info"

        self.token_endpoint = self.info.get('token_endpoint')
        self.oauth_token_endpoint = join(self.token_endpoint, '/oauth/token')
        self.token_keys_endpoint = join(self.token_endpoint, '/token_keys')
        self.app_ssh_key_fingerprint = self.info.get('app_ssh_key_fingerprint')
        self.logging_endpoint = self.info.get('logging_endpoint')
        self.doppler_logging_endpoint = self.info.get('doppler_logging_endpoint')
        self.authorization_endpoint = self.info.get('authorization_endpoint')

    def get(self, url, params=None, **kwargs):
        kwargs.update({'verify': self.ssl_verify})
        return requests.get(url, params, **kwargs)

    @test
    def well_known_keys(self):

        """ Well-known cryptographic keys """

        manifests = [
            'https://raw.githubusercontent.com/cloudfoundry/uaa/master/uaa/src/main/resources/uaa.yml',
            'https://raw.githubusercontent.com/cloudfoundry/cloud_controller_ng/master/config/bosh-lite.yml',
            'https://raw.githubusercontent.com/cloudfoundry/cloud_controller_ng/master/config/cloud_controller.yml'
        ]

        manifest_data = '\n'.join(map(lambda x: self.get(x).text, manifests))

        token_keys = self.get(self.token_keys_endpoint).json()

        for token_key in token_keys.get('keys'):
            first_line = token_key.get('value').split('\n')[1]
            if first_line in manifest_data:
                yield FAIL, 'key "%s..." is a default token signing key and should be changed immediately' % first_line
            else:
                yield PASS, 'key "%s..." is not a default token signing key' % first_line

        if self.app_ssh_key_fingerprint:
            if self.app_ssh_key_fingerprint in manifest_data:
                yield FAIL, 'app SSH is using the default SSH host key "%s", should be changed immediately' % app_ssh_key
            else:
                yield PASS, 'app SSH is using a non-default SSH Host key "%s"' % app_ssh_key


    @test
    def platform_uaa_version(self):

        """ Platform UAA version """

        latest_version = self.get(
            "https://raw.githubusercontent.com/cloudfoundry/uaa/master/gradle.properties",
        ).text.split('=')[-1]

        current_version = self.get(
            join(self.info.get('token_endpoint'), '/login'),
            headers={'accept': 'application/json'}
        ).json()

        latest_major, latest_minor = parse_version(latest_version)
        major, minor = parse_version(current_version.get('app', {'version': '0.0.0'}).get('version'))

        if major < latest_major or minor < latest_minor:
            yield FAIL, 'UAA version is %d.%d, latest version is %d.%d' % (major, minor, latest_major, latest_minor)
        else:
            yield PASS, 'UAA is at latest version %s' % latest_version

    @test
    def cf_version(self):

        """ Cloud Foundry version and known CVEs """

        latest_version = self.get(
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

        fail = False

        for creds in well_knwon_creds:

            attempt = self.get(
                self.oauth_token_endpoint,
                params={"grant_type": "client_credentials"},
                auth=HTTPBasicAuth(*creds)
            )

            if attempt.status_code == 200:
                yield FAIL, 'UAA is uses well-known credential "%s:%s"' % creds
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
            attempt = self.get(join(self.target, '/internal/buildpacks'), auth=HTTPBasicAuth(*creds))
            if attempt.status_code == 200:
                fail = True
                break

        if fail:
            yield FAIL, 'Cloud Controller uses well-known credential "%s:%s" for cloud controller internal api' % creds
        else:
            yield PASS, 'Cloud Controller does not use well-known internal api credentials'


    @test
    def insecure_protocols(self):

        """ Insecure communication protocols """

        http_urls = [
            self.token_endpoint,
            self.authorization_endpoint,
            self.target
        ]

        ws_urls = [
            self.logging_endpoint,
            self.doppler_logging_endpoint
        ]

        for url in http_urls:

            if not url:
                continue

            insecure = urlparse.urlparse(url)
            insecure_url = urlparse.urlunparse(('http', insecure.hostname, '/', None, None, None))

            try:
                attempt = self.get(insecure_url, allow_redirects=False)
                if attempt.status_code == 200:
                    yield FAIL, 'endpoint "%s" accessible over insecure http://, should only be https://' % insecure.hostname
                if 300 <= attempt.status_code < 400:
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
                attempt = self.get(insecure_url, allow_redirects=False)
                if attempt.status_code == 200 or attempt.status_code == 404:
                    yield FAIL, 'endpoint "%s" accessible over insecure ws://, should only be wss://' % insecure.hostname
                if 300 <= attempt.status_code < 400:
                    yield FAIL, 'endpoint "%s" accessible over insecure ws://, ' \
                                 'but automatically redirects to wss://, ' \
                                 'this could lead to man-in-the-middle attacks' % insecure.hostname
            except:
                yield PASS, 'endpoint "%s" not accessible over ws://' % insecure.hostname

