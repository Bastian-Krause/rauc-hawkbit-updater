import os
import sys
from configparser import ConfigParser
from tempfile import NamedTemporaryFile

import pytest

from hawkbit import HawkbitMgmtTestClient, HawkbitError
from helper import run_pexpect, available_port

def pytest_addoption(parser):
    """Register custom argparse-style options."""
    parser.addoption(
        '--keep-configs',
        action='store_true',
        help='Do not delete temporary configs after test run',
        default=False)
    parser.addoption(
        '--hawkbit-instance',
        help='HOST:PORT of hawkBit instance to use (default: %(default)s)',
        default='localhost:8080')

@pytest.fixture(scope='session')
def hawkbit(pytestconfig):
    """Instance of HawkbitMgmtTestClient connecting to a hawkBit instance."""
    host, port = pytestconfig.option.hawkbit_instance.split(':')
    client = HawkbitMgmtTestClient(host, int(port))

    client.set_config('pollingTime', '00:00:30')
    client.set_config('pollingOverdueTime', '00:03:00')
    client.set_config('authentication.targettoken.enabled', True)
    client.set_config('authentication.gatewaytoken.enabled', True)
    client.set_config('authentication.gatewaytoken.key', 'mah4Ooze2Oog5oohae4IeWiCiu9gie4ei')

    return client

@pytest.fixture
def hawkbit_target_added(hawkbit):
    """Creates a hawkBit target."""
    target = hawkbit.add_target()
    yield target

    hawkbit.delete_target(target)

@pytest.fixture
def config(pytestconfig, hawkbit, hawkbit_target_added):
    """
    Creates a temporary rauc-hawkbit-updater configuration matching the hawkBit (target)
    configuration of the hawkbit and hawkbit_target_added fixtures.
    """
    target = hawkbit.get_target()
    target_token = target.get('securityToken')
    target_name = target.get('name')
    bundle_location = NamedTemporaryFile(mode='r', delete=False)
    bundle_location.close()

    config = ConfigParser()
    config['client'] = {
        'hawkbit_server': f'{hawkbit.host}:{hawkbit.port}',
        'ssl': 'false',
        'ssl_verify': 'false',
        'tenant_id': 'DEFAULT',
        'target_name': target_name,
        'auth_token': target_token,
        'bundle_download_location': bundle_location.name,
        'retry_wait': '60',
        'connect_timeout': '20',
        'timeout': '60',
        'log_level': 'debug',
    }
    config['device'] = {
        'product': 'Terminator',
        'model': 'T-1000',
        'serialnumber': '8922673153',
        'hw_revision': '2',
        'mac_address': 'ff:ff:ff:ff:ff:ff',
    }

    tmp_config = NamedTemporaryFile(mode='w', delete=False)
    config.write(tmp_config)
    tmp_config.close()
    yield tmp_config.name

    try:
        os.unlink(bundle_location.name)
    except FileNotFoundError:
        pass

    if not pytestconfig.option.keep_configs:
        os.unlink(tmp_config.name)

@pytest.fixture
def adjust_config(pytestconfig, config):
    """
    Adjusts the rauc-hawkbit-updater configuration created by the config fixture by
    adding/overwriting or removing options.
    """
    config_files = []
    def _adjust_config(options={'client': {}}, remove={}):
        adjusted_config = ConfigParser()
        adjusted_config.read(config)

        # update
        for section, option in options.items():
            for key, value in option.items():
                adjusted_config.set(section, key, value)

        # remove
        for section, option in remove.items():
            adjusted_config.remove_option(section, option)

        tmp_config = NamedTemporaryFile(mode='w', delete=False)
        adjusted_config.write(tmp_config)
        tmp_config.close()
        config_files.append(tmp_config.name)
        return tmp_config.name

    yield _adjust_config

    if not pytestconfig.option.keep_configs:
        for config_file in config_files:
            os.unlink(config_file)

@pytest.fixture(scope='session')
def rauc_bundle():
    """Creates a temporary 512 KB file to be used as a dummy RAUC bundle."""
    bundle = NamedTemporaryFile(delete=False)
    bundle.write(os.urandom(512)*1024)
    bundle.close()
    yield bundle.name

    os.unlink(bundle.name)

@pytest.fixture
def bundle_assigned(hawkbit, hawkbit_target_added, rauc_bundle):
    """
    Creates a softwaremodule containing the file from the rauc_bundle fixture as an artifact.
    Creates a distributionset from this softwaremodule. Assigns this distributionset to the target
    created by the hawkbit_target_added fixture. Returns the corresponding action ID of this
    assignment.
    """
    swmodule = hawkbit.add_softwaremodule()
    artifact = hawkbit.add_artifact(rauc_bundle, swmodule)
    distributionset = hawkbit.add_distributionset(swmodule)
    action = hawkbit.assign_target(distributionset)

    yield action

    try:
        hawkbit.cancel_action(action, hawkbit_target_added, force=True)
    except HawkbitError:
        pass

    hawkbit.delete_distributionset(distributionset)
    hawkbit.delete_artifact(artifact, swmodule)
    hawkbit.delete_softwaremodule(swmodule)

@pytest.fixture
def rauc_dbus_install_success(rauc_bundle):
    """
    Creates a RAUC D-Bus dummy interface on the SessionBus mimicing a successful installation on
    Install().
    """
    proc = run_pexpect(f'{sys.executable} -m rauc_dbus_dummy {rauc_bundle}', cwd='test')
    proc.expect('Interface published')

    yield

    assert proc.isalive()
    proc.terminate()

@pytest.fixture
def rauc_dbus_install_failure(rauc_bundle):
    """
    Creates a RAUC D-Bus dummy interface on the SessionBus mimicing a failing installation on
    Install().
    """
    proc = run_pexpect(f'{sys.executable} -m rauc_dbus_dummy {rauc_bundle} --completed-code=1',
                       cwd='test', timeout=None)
    proc.expect('Interface published')

    yield

    assert proc.isalive()
    proc.terminate(force=True)

@pytest.fixture(scope='session')
def nginx_config(pytestconfig):
    """
    Creates a temporary nginx proxy configuration incorporating additional given options to the
    location section.
    """
    config_template = """
daemon off;
pid /tmp/hawkbit-nginx-{port}.pid;

# non-fatal alert for /var/log/nginx/error.log will still be shown
# https://trac.nginx.org/nginx/ticket/147
error_log stderr notice;

events {{ }}

http {{
    access_log /dev/null;

    server {{
        listen {port};

        location / {{
            proxy_pass http://localhost:8080;
            {location_options}

            # use proxy URL in JSON responses
            sub_filter "localhost:$proxy_port/" "$host:$server_port/";
            sub_filter "$host:$proxy_port/" "$host:$server_port/";
            sub_filter_types application/json;
            sub_filter_once off;
        }}
    }}
}}"""
    configs = []

    def _nginx_config(port, location_options):
        tmp_config = NamedTemporaryFile(mode='w', delete=False)
        location_options = ( f'{key} {value};' for key, value in location_options.items())
        config = config_template.format(port=port, location_options=" ".join(location_options))
        tmp_config.write(config)
        tmp_config.close()
        configs.append(tmp_config.name)
        return tmp_config.name

    yield _nginx_config

    if not pytestconfig.option.keep_configs:
        for config in configs:
            os.unlink(config)

@pytest.fixture(scope='session')
def nginx_proxy(nginx_config):
    """
    Runs an nginx rate liming proxy, limiting download speeds to 70 KB/s. HTTP requests are
    forwarded to port 8080 (default port of the docker hawkBit instance). Returns the port the
    proxy is running on. This port can be set in the rauc-hawkbit-updater config to rate limit its
    HTTP requests.
    """
    import pexpect

    procs = []

    def _nginx_proxy(options):
        port = available_port()
        config = nginx_config(port, options)

        try:
            proc = run_pexpect(f'nginx -c {config} -p .', timeout=None)
        except (pexpect.exceptions.EOF, pexpect.exceptions.ExceptionPexpect):
            pytest.skip('nginx unavailable')

        try:
            proc.expect('start worker process ')
        except pexpect.exceptions.EOF:
            pytest.skip('nginx failed, use -s to see logs')

        procs.append(proc)

        return port

    yield _nginx_proxy

    for proc in procs:
        assert proc.isalive()
        proc.terminate(force=True)

@pytest.fixture(scope='session')
def rate_limited_port(nginx_proxy):
    """
    Runs an nginx rate liming proxy, limiting download speeds to 70 KB/s. HTTP requests are
    forwarded to port 8080 (default port of the docker hawkBit instance). Returns the port the
    proxy is running on. This port can be set in the rauc-hawkbit-updater config to rate limit its
    HTTP requests.
    """
    def _rate_limited_port(rate):
        location_options = {'proxy_limit_rate': rate}
        return nginx_proxy(location_options)

    yield _rate_limited_port
