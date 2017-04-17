import os

from vault_mods.api_base import VaultAPIBase
from vault_mods.utils import is_success
from vault_mods import enums


class System(VaultAPIBase):
    SecretBackend = enums.SecretBackend

    def __init__(
            self,
            server_url: str = 'http://127.0.0.1/',
            api_version: str = 'v1',
            loop=None,
            cafile: str = '',
            token: str = '',
            tcp_connector=None,
    ):
        self.server_url = server_url
        self.api_url = os.path.join(self.server_url, api_version)
        self.sys_url = os.path.join(self.api_url, 'sys')

        self.URLS = {
            'mounts': {
                'list': os.path.join(self.sys_url, 'mounts'),
                'mount': os.path.join(self.sys_url, 'mounts', '%(path)s'),
                'config': os.path.join(self.sys_url, 'mounts', '%(path)s', 'tune'),
            },
        }
        super().__init__(token=token, cafile=cafile, loop=loop, tcp_connector=tcp_connector, api_version=api_version)

    def list_mounts(self) -> dict:
        response = self.af.go_single(self.list_mount_task())
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']

    def list_mount_task(self) -> dict:
        return self.mk_task_bundle(self.url('mounts', 'list'), method='get')

    def mount(self, backend_type: enums.SecretBackend, mount_point: str= 'mount-point',
              description: str='', config: dict=None):
        response = self.af.go_single(self.mount_task(
            backend_type, mount_point, description, config
        ))
        if not is_success(response.status):
            raise Exception(response)
        if backend_type == enums.SecretBackend.Transit:
            from vault_mods.transit import Transit
            return Transit(
                server_url=self.server_url,
                api_version=self.api_version,
                mount_point=mount_point,
                loop=self.loop,
                cafile=self.cafile,
                token=self.token,
                tcp_connector=self.get_tcp_connector(),
                parent=self
            )

        return response.result

    def mount_task(self, backend_type: enums.SecretBackend, mount_point: str= 'mount-point',
                   description: str='', config: dict=None) -> dict:
        if backend_type not in self.SecretBackend:
            raise ValueError('Unknown backend type: `%s`' % backend_type)
        if config:
            diff = set(config.keys()).difference(set(e.name for e in enums.AllowedSecretBackendConfigKeys))
            if diff:
                raise ValueError('Wrong keys passed into config: %s' % diff)

        url = self.url('mounts', 'mount', path=mount_point)
        data_bundle = {
            'type': backend_type.value,
            'description': description,
            'config': config or {},
        }
        return self.mk_task_bundle(url, data=data_bundle, method='post')

    def unmount(self, mount_point: str):
        response = self.af.go_single(self.unmount_task(mount_point))
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def unmount_task(self, mount_point: str):
        url = self.url('mounts', 'mount', path=mount_point)
        return self.mk_task_bundle(url, method='delete')

    def mount_read_config(self, mount_point: str):
        response = self.af.go_single(self.mount_read_config_task(mount_point))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']

    def mount_read_config_task(self, mount_point: str):
        url = self.url('mounts', 'config', path=mount_point)
        return self.mk_task_bundle(url, method='get')

    def mount_write_config(self, mount_point: str, default_lease_ttl: str= '0', max_lease_ttl: str= '0') -> None:
        response = self.af.go_single(self.mount_write_config_task(mount_point, default_lease_ttl, max_lease_ttl))
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def mount_write_config_task(self, mount_point: str, default_lease_ttl: str= '0', max_lease_ttl: str= '0') -> dict:
        url = self.url('mounts', 'config', path=mount_point)
        return self.mk_task_bundle(url, method='post', data={
            'default_lease_ttl': default_lease_ttl, 'max_lease_ttl': max_lease_ttl
        })
