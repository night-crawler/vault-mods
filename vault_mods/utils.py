import aiohttp
import ssl
import typing as t

from base64 import b64encode, b64decode, b32encode, b32decode

bytes_or_str = t.Union[str, bytes]


def is_informational(code):
    return 100 <= code <= 199


def is_success(code):
    return 200 <= code <= 299


def is_redirect(code):
    return 300 <= code <= 399


def is_client_error(code):
    return 400 <= code <= 499


def is_server_error(code):
    return 500 <= code <= 599


class TCPConnectorMixIn:

    def get_tcp_connector(self) -> aiohttp.TCPConnector:
        if self._connector_owner:
            # return valid connector
            if self._tcp_connector and not self._tcp_connector.closed:
                return self._tcp_connector
            # create ssl context if no valid connector is present
            ssl_context = ssl.create_default_context(cafile=self.cafile)

            # memoize tcp_connector
            self._tcp_connector = aiohttp.TCPConnector(loop=self.loop, ssl_context=ssl_context, keepalive_timeout=60)
            return self._tcp_connector

        return self._tcp_connector

    def __del__(self):
        if self._connector_owner:
            connector = self.get_tcp_connector()
            not connector.closed and connector.close()


def b64_encode(raw_str: bytes_or_str) -> str:
    if isinstance(raw_str, str):
        b64_bytes = b64encode(raw_str.encode())
    else:
        b64_bytes = b64encode(raw_str)
    return b64_bytes.decode()


def b64_decode(b64_string: str, encoding=None) -> bytes_or_str:
    _bytes = b64decode(b64_string)
    if encoding:
        return _bytes.decode(encoding)
    return _bytes


def b32_encode(raw_str: bytes_or_str) -> str:
    if isinstance(raw_str, str):
        b64_bytes = b32encode(raw_str.encode())
    else:
        b64_bytes = b32encode(raw_str)
    return b64_bytes.decode()


def b32_decode(b32_string: str, encoding=None) -> bytes_or_str:
    _bytes = b32decode(b32_string)
    if encoding:
        return _bytes.decode(encoding)
    return _bytes


def b64_dict_encode(d: dict) -> dict:
    return {k: b64_encode(v) for k, v in d.items() if v}


def restore_padding(raw_str: str, n: int=8, c: str='=') -> str:
    """
    :param raw_str: string with broken padding
    :param n: padding 
    :param c: character
    :return: padded base32/base64 string
    """
    return raw_str + c*(-len(raw_str) % n)
