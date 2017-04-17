import typing as t
import asyncio
import aiohttp
import json
import time

from furl import furl
from collections import OrderedDict, namedtuple
from django.utils.translation import ugettext_lazy as _

from vault_mods.utils import TCPConnectorMixIn

FetchResult = namedtuple('FetchResult', ['headers', 'result', 'status', 'url'])


def get_or_create_event_loop() -> t.Union[asyncio.BaseEventLoop, asyncio.AbstractEventLoop]:
    try:
        loop = asyncio.get_event_loop()
        return loop
    except (RuntimeError, AssertionError):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


class AsyncFetch(TCPConnectorMixIn):
    def __init__(self,
                 task_map: dict, timeout: int=10, num_retries: int=0, retry_timeout: float=1,
                 cafile: str=None,
                 loop: t.Union[asyncio.BaseEventLoop, asyncio.AbstractEventLoop, None]=None,
                 tcp_connector=None,
                 service_name: str=None):
        self.task_map = OrderedDict(task_map.items())
        self.timeout = timeout
        self.num_retries = num_retries
        self.retry_timeout = retry_timeout
        self.service_name = service_name
        self.cafile = cafile
        self.loop = loop or get_or_create_event_loop()
        self._tcp_connector = tcp_connector
        self._connector_owner = not bool(tcp_connector)

    @staticmethod
    def mk_task(url: str, data=None, method: str=None,
                headers: dict=None, response_type: str='json', timeout: float=None,
                query_params: dict=None) -> dict:
        if query_params:
            url = furl(url).set(query_params).url

        headers = headers or {}
        if 'content-type' not in headers:
            if isinstance(data, dict):
                headers['content-type'] = 'application/json'
            elif isinstance(data, str):
                headers['content-type'] = 'text/html'
        if isinstance(data, dict):
            data = json.dumps(data)
        bundle = {
            'method': method or 'get',
            'url': url,
            'data': data or {},
            'headers': headers,
            'response_type': response_type,
            'timeout': timeout,
        }
        return bundle

    def get_client_session(self):
        return aiohttp.ClientSession(
            connector=self.get_tcp_connector(),
            connector_owner=self._connector_owner
        )

    @asyncio.coroutine
    def fetch(self, session: aiohttp.ClientSession, bundle: dict) -> FetchResult:
        aio_bundle = bundle.copy()
        method, url = aio_bundle.pop('method', 'get'), aio_bundle.pop('url')
        response_type = aio_bundle.pop('response_type')
        timeout = aio_bundle.pop('timeout') or self.timeout

        with aiohttp.Timeout(timeout):
            response = yield from session.request(method, url, **aio_bundle)
            if response.status == 502:
                yield from response.release()
                raise TimeoutError

            if response_type == 'json' and response_type not in response.content_type:
                gen = getattr(response, 'text')()
            else:
                gen = getattr(response, response_type)()

            res = yield from gen

            return FetchResult(result=res, headers=response.headers, status=response.status, url=url)

    def go(self) -> OrderedDict:
        try:
            with self.get_client_session() as session:
                tasks = [self.fetch(session, bundle) for bundle in self.task_map.values()]
                res = self.loop.run_until_complete(asyncio.gather(*tasks))
                return OrderedDict(zip(self.task_map.keys(), res))
        except (aiohttp.ClientOSError, TimeoutError):
            if self.num_retries > 0:
                self.num_retries -= 1
                time.sleep(self.retry_timeout)
                return self.go()
            else:
                raise Exception(_('Failed to connect to %s service' % self.service_name or 'api'))
        except ValueError:
            raise Exception(_('Failed to receive data from %s service' % self.service_name or 'api'))

    def go_single(self, bundle) -> FetchResult:
        with self.get_client_session() as session:
            return self.loop.run_until_complete(self.fetch(session, bundle))
