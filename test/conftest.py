import os
from configparser import ConfigParser
from tempfile import NamedTemporaryFile

import pytest

from hawkbit import HawkbitMgmtTestClient, HawkbitError

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
