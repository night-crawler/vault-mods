import ssl
import asyncio
import typing as t

from collections import OrderedDict

from vault_mods.async_fetcher import AsyncFetch, get_or_create_event_loop
from vault_mods.utils import TCPConnectorMixIn


class VaultAPIBase(TCPConnectorMixIn):
    URLS = {}

    def __init__(
            self,
            loop: t.Union[asyncio.BaseEventLoop, asyncio.AbstractEventLoop, None]=None,
            cafile: str='',
            token: str='',
            tcp_connector=None,
            api_version='v1',
            parent: 'VaultAPIBase'=None,
    ):
        self.task_map = OrderedDict()

        self.ssl_context = ssl.create_default_context()
        self.cafile = cafile
        self.loop = loop or self.get_loop()
        self.token = token
        self.api_version = api_version

        if parent:
            self._tcp_connector = parent.get_tcp_connector()
            self._connector_owner = False
        else:
            self._tcp_connector = tcp_connector
            self._connector_owner = not bool(tcp_connector)

        # must keep parent to prevent socket close via __del__
        self.parent = parent
        self.af = self.get_async_fetcher()

    # noinspection PyMethodMayBeStatic
    def get_loop(self) -> t.Union[asyncio.BaseEventLoop, asyncio.AbstractEventLoop]:
        return get_or_create_event_loop()

    def get_async_fetcher(self, task_map: dict=None):
        task_map = task_map or {}
        return AsyncFetch(
            task_map,
            cafile=self.cafile, loop=self.loop,
            # AsyncFetch never should never own connectors. VaultAPIBase must close connection on exit.
            tcp_connector=self.get_tcp_connector()
        )

    def get_headers(self) -> dict:
        return {
            'content-type': 'application/json',
            'X-Vault-Token': self.token,
        }

    def url(self, category: str, action: str, **kwargs) -> str:
        return self.URLS[category][action] % kwargs

    def mk_task_bundle(self, *args, **kwargs) -> dict:
        headers = kwargs.pop('headers', self.get_headers())
        return AsyncFetch.mk_task(*args, headers=headers, **kwargs)

    def go(self) -> OrderedDict:
        af = self.get_async_fetcher(self.task_map)
        return af.go()

    def append_task(self, dkey: str, task_bundle: dict) -> None:
        self.task_map[dkey] = task_bundle

    def go_tasks(self, *task_bundles):
        task_map = OrderedDict()
        for i, task_bundle in enumerate(task_bundles):
            task_map[i] = task_bundle
        return self.get_async_fetcher(task_map).go()
