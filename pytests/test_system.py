from pprint import pprint

import pytest
from vault_mods.system import System
from . import settings


@pytest.fixture(scope='module')
def system_instance():
    return System(
        server_url=settings.TRANSIT['SERVER_URL'],
        token=settings.TRANSIT['TOKEN'],
        cafile=settings.TRANSIT['CAFILE']
    )


# noinspection PyMethodMayBeStatic,PyShadowingNames
class SystemBackendTest:

    def test_list_mounts(self, system_instance: System):
        system_instance.list_mounts()

    # pre unmount backend
    def test_unmount(self, system_instance: System):
        system_instance.unmount('example.com/test/generic')

    def test_wrong_config(self, system_instance: System):
        with pytest.raises(ValueError):
            system_instance.mount(
                System.SecretBackend.Generic,
                mount_point='example.com/test/generic', description='vasya', config={'wrong': 1})

    def test_wrong_backend(self, system_instance: System):
        with pytest.raises(ValueError):
            system_instance.mount('lol', mount_point='example.com/test/generic', description='vasya')

    def test_mount_generic(self, system_instance: System):
        system_instance.mount(
            System.SecretBackend.Generic,
            mount_point='example.com/test/generic', description='vasya', config={})

    def test_mount_read_config(self, system_instance: System):
        system_instance.mount_read_config('example.com/test/generic')

    def test_mount_write_config(self, system_instance: System):
        assert system_instance.mount_write_config('example.com/test/generic', '10h', '10h') is None

    def test_mount_transit(self, system_instance: System):
        system_instance.unmount('example.com/transit')
        transit = system_instance.mount(System.SecretBackend.Transit, 'example.com/transit', description='NONONO')
        from vault_mods.transit import Transit
        assert isinstance(transit, Transit)

        lolkey = transit.get_key('lol')
        lolkey.create_key()
        lolkey.encrypt_data('yaaa')
