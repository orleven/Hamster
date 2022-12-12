#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

"""
在原aiohttp上封装一层，便于请求的控制
"""

import json
import traceback
import aiohttp
from lib.core.env import *
from yarl import URL
from typing import Any
from typing import Union
from typing import Type
from typing import Optional
from types import TracebackType
from aiohttp_socks import SocksConnector
from mitmproxy.websocket import WebSocketMessage
from aiohttp.client import hdrs
from aiohttp.client import TCPConnector
from aiohttp.client import _RequestContextManager
from aiohttp.client import _WSRequestContextManager
from aiohttp.client_exceptions import asyncio
from aiohttp.client_exceptions import ServerDisconnectedError
from aiohttp.client_exceptions import ClientConnectorError
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.client_exceptions import ClientOSError
from aiohttp.client_exceptions import TooManyRedirects
from asyncio.exceptions import TimeoutError
from lib.core.g import log
from lib.core.g import redis
from lib.core.g import cache_log
from lib.core.g import conf
from lib.core.g import cache_queue
from lib.core.g import vul_queue
from lib.core.g import path_queue
from lib.core.g import param_queue
from lib.core.g import packet_queue
from lib.core.g import email_queue
from lib.core.g import jsonp_queue
from lib.core.g import cors_queue
from addon import BaseAddon
from lib.core.enums import ScanMode
from lib.core.enums import WebsocketType
from lib.util.util import random_ua
from lib.util.util import ip_header
from lib.util.util import get_base_url
from lib.util.util import get_time_str


class ClientSession(aiohttp.ClientSession):
    """
    重写ClientSession的_request函数，功能与原相同
    """

    def __init__(self, addon_path, max_retries=0, retry_interval=5, max_fail_redirects=3, **kwargs):
        """
        :param retry_interval: 重试间隔
        :param max_retries: 重试次数
        :param max_fail_redirects: 抛出TooManyRedirects错误后，重定向次数
        :param kwargs:
        """

        if kwargs.get('connector') is None:
            connector = TCPConnector(ssl=False)
            try:
                if MAIN_NAME != 'simple' and conf.agent.hasattr("support_proxy") and conf.agent.support_proxy.startswith('socks5'):
                    connector = SocksConnector.from_url(conf.agent.support_proxy)
            except:
                pass
            finally:
                kwargs.setdefault('connector', connector)

        self.__addon_path = addon_path
        self.__max_data_queue_num = conf.basic.max_data_queue_num
        self.__max_retries = max_retries if max_retries >= 0 else 0
        self.__retry_interval = retry_interval
        self.__max_fail_redirects = max_fail_redirects
        self.__redis_qps_limit_prefix = REDIS_SCAN_QPS_LIMIT_PREFIX
        self.__qps_limit = conf.scan.scan_qps_limit
        self.__scan_mode = conf.scan.scan_mode
        self.__is_save_request_body = conf.cache.is_save_request_body
        self.__is_save_response_body = conf.cache.is_save_response_body
        self.__save_body_size_limit = conf.cache.save_body_size_limit
        super().__init__(**kwargs)

    async def qps_limit(self, url):
        """
        qps 扫描限制
        """

        if MAIN_NAME == 'agent':
            base_url = get_base_url(url)
            hash = '|'.join([self.__redis_qps_limit_prefix, get_time_str(), base_url])
            try:
                count = await redis.redis_conn.get(hash)
                while count and int(count) > self.__qps_limit:
                    await asyncio.sleep(0.1)
                    count = await redis.redis_conn.get(hash)
                await redis.redis_conn.incr(hash, 1)
                await redis.redis_conn.expire(hash, 10)
            except:
                pass

    def request(self, method: str, url: Union[str, URL], **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP request."""
        if not kwargs.get('read_until_eof', True):
            return RequestContextManager(super()._request(method, url, **kwargs))
        return RequestContextManager(self._request(method, url, **kwargs))

    def get(self, url: Union[str, URL], *, allow_redirects: bool = True, **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP GET request."""
        return RequestContextManager(self._request(hdrs.METH_GET, url, allow_redirects=allow_redirects, **kwargs))

    def options(self, url: Union[str, URL], *, allow_redirects: bool = True, **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP OPTIONS request."""
        return RequestContextManager(self._request(hdrs.METH_OPTIONS, url, allow_redirects=allow_redirects, **kwargs))

    def head(self, url: Union[str, URL], *, allow_redirects: bool = False, **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP HEAD request."""
        return RequestContextManager(self._request(hdrs.METH_HEAD, url, allow_redirects=allow_redirects, **kwargs))

    def post(self, url: Union[str, URL], *, data: Any = None, **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP POST request."""
        return RequestContextManager(self._request(hdrs.METH_POST, url, data=data, **kwargs))

    def put(self, url: Union[str, URL], *, data: Any = None, **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP PUT request."""
        return RequestContextManager(self._request(hdrs.METH_PUT, url, data=data, **kwargs))

    def patch(self, url: Union[str, URL], *, data: Any = None, **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP PATCH request."""
        return RequestContextManager(self._request(hdrs.METH_PATCH, url, data=data, **kwargs))

    def delete(self, url: Union[str, URL], **kwargs: Any) -> "RequestContextManager":
        """Perform HTTP DELETE request."""
        return RequestContextManager(self._request(hdrs.METH_DELETE, url, **kwargs))

    def ws_connect(self, url: Union[str, URL], **kwargs: Any) -> "WSRequestContextManager":
        """Initiate websocket connection."""
        return WSRequestContextManager(self._ws_connect(url, **kwargs))


    def __pre_deal(self, ws_flag=False, **kwargs):
        """参数预处理"""

        # 关闭ssl验证
        kwargs.setdefault('verify_ssl', False)

        # 增加默认ua
        headers = kwargs.get('headers', {})
        user_agent = headers.get("User-Agent", 'aiohttp')
        if 'aiohttp' in user_agent:
            headers["User-Agent"] = random_ua()

        if not ws_flag:
            # 设置timeout
            if kwargs.get('timeout') is None:
                kwargs.setdefault('timeout', conf.basic.timeout)

            # 增加X-Forwarded-For等字段
            if 'API-Key' not in headers.keys():
                for key, value in ip_header().items():
                    if key not in headers.keys():
                        headers[key] = value

        # 设置cookie
        cookie = headers.get("Cookie", None)
        if isinstance(cookie, dict):
            headers['Cookie'] = '; '.join(['='.join([key, value]) for key, value in cookie.items()])

        # 设置headers
        kwargs.setdefault('headers', headers)

        if kwargs.get('proxy') is None:
            if MAIN_NAME != 'simple' and conf.agent.hasattr("support_proxy") and conf.agent.support_proxy.startswith('http'):
                kwargs.setdefault('proxy', conf.agent.support_proxy)

        return kwargs

    async def _ws_connect(self, url, keyword: str = None, message_list=None, message: WebSocketMessage = None, **kwargs):
        """
        重写_ws_connect函数，功能与原相同， 增加默认代理等配置
        """
        if message_list is None:
            message_list = []

        kwargs = self.__pre_deal(True, **kwargs)

        method = kwargs.get("method", hdrs.METH_GET)
        total = self.__max_retries + 1
        for count in range(total):
            if count > 0:
                log.warning(f'Request to {url} failed, retrying ({count} / {total})...')
            else:
                log.debug(f'Request to {url}')

            try:
                await self.qps_limit(url)
                resp = await super()._ws_connect(url, **kwargs)

                temp = []
                for message in message_list:
                    temp.append({"is_text": message.is_text, "from_client": message.from_client, "content": message.content.decode('utf-8')})
                if message:
                    temp.append({"is_text": message.is_text, "from_client": True, "content": message.content.decode('utf-8')})
                    resp.__dict__['websocket_type'] = WebsocketType.TEXT if message.is_text else WebsocketType.BINARY
                else:
                    resp.__dict__['websocket_type'] = WebsocketType.BINARY
                resp.__dict__['websocket_content'] = bytes(json.dumps(temp), 'utf-8')

                # 保存缓存
                if keyword:
                    await self.__save_cache(keyword, resp)

                return resp
            except TooManyRedirects:
                kwargs.setdefault('allow_redirects', False)
                kwargs.setdefault('max_redirects', self.__max_fail_redirects)
                await self.qps_limit(url)
                return await super()._ws_connect(url, **kwargs)
            except (TimeoutError, ClientOSError, ClientResponseError, ClientConnectorError, ServerDisconnectedError):
                pass
            except Exception as e:
                traceback.print_exc()
                err = str(e).strip()
                if err != '' and 'InvalidServerVersion' not in err and 'Unexpected SOCKS' not in err:
                    log.error(f"Error request, url: {url}, error: {err}")
            await asyncio.sleep(self.__retry_interval)

        if keyword:
            headers = kwargs.get('headers', {})
            await self.__save_cache_by_none(keyword, method, url, headers, message.is_text)
        return None

    async def _request(self, method, url, keyword: str = None, **kwargs):
        """
        重写_request函数，功能与原相同， 增加默认代理等配置
        """
        kwargs = self.__pre_deal(False, **kwargs)

        # 处理data
        json_data = kwargs.get('json', None)
        if json_data:
            data = json.dumps(json_data)
        else:
            data = kwargs.get('data', None)
        if data:
            if isinstance(data, str):
                data = bytes(data, 'utf-8')
        else:
            data = b''

        total = self.__max_retries + 1
        for count in range(total):
            if count > 0:
                log.warning(f'Request to {url} failed, retrying ({count} / {total})...')
            else:
                log.debug(f'Request to {url}')

            try:
                await self.qps_limit(url)
                resp = await super()._request(method, url, **kwargs)

                # 临时加入request_content参数，便于数据包存储
                resp.__dict__['request_content'] = data

                # 保存缓存
                if keyword:
                    await self.__save_cache(keyword, resp)

                return resp
            except TooManyRedirects:
                kwargs.setdefault('allow_redirects', False)
                kwargs.setdefault('max_redirects', self.__max_fail_redirects)
                await self.qps_limit(url)
                try:
                    return await super()._request(method, url, **kwargs)
                except:
                    return None
            except (TimeoutError, ClientOSError, ClientResponseError, ClientConnectorError, ServerDisconnectedError):
                pass
            except Exception as e:
                err = str(e).strip()
                if err != '' and 'InvalidServerVersion' not in err and 'Unexpected SOCKS' not in err:
                    request_headers = kwargs.get('headers', {})
                    request_content = kwargs.get('data', None)
                    log.error(f"Error request, method: {method}, url: {url}, headers: {request_headers}, request_content: {request_content}, error: {err}")
                    traceback.print_exc()
            await asyncio.sleep(self.__retry_interval)

            # 保存缓存
        if keyword:
            headers = kwargs.get('headers', {})
            await self.__save_cache_by_none(keyword, method, url, headers, data)

        return None


    async def __save_cache(self, keyword, packet):
        """保存扫描的缓存数据包"""

        cache = await BaseAddon.parser_packet(packet)
        if cache:
            cache["keyword"] = keyword

            if self.__is_save_request_body:
                request_content = cache.get("request_content", b'')
                cache["request_content"] = request_content[:self.__save_body_size_limit] if request_content else None
            else:
                cache["request_content"] = None

            if self.__is_save_response_body:
                response_content = cache.get("response_content", b'')
                cache["response_content"] = response_content[:self.__save_body_size_limit] if response_content else None
            else:
                cache["response_content"] = None

            websocket_content = cache.get("websocket_content", b'')
            cache["websocket_content"] = websocket_content[:self.__save_body_size_limit] if websocket_content else None

            # 记录日志
            self.__print_cache_log(cache)

            if self.__scan_mode == ScanMode.CACHE:
                await self.__put_queue(cache, cache_queue)

    async def __save_cache_by_none(self, keyword, method, url, headers, data=None):
        """保存扫描的缓存数据包"""

        if isinstance(data, WebSocketMessage):
            packet = {
                "method": method,
                "url": url,
                "headers": headers,
                "request_content": None,
                "websocket_content": data.content,
                "websocket_type": WebsocketType.TEXT if data.is_text else WebsocketType.BINARY
            }
        else:
            packet = {
                "method": method,
                "url": url,
                "headers": headers,
                "request_content": data,
                "websocket_content": None,
                "websocket_type": None,
            }
        await self.__save_cache(keyword, packet)


    def __print_cache_log(self, cache):
        """记录缓存日志"""

        addon_path = self.__addon_path
        keyword = cache.get("keyword", None)
        method = cache.get("method", None)
        url = cache.get("url", None)
        status = cache.get("response_status_code", None)
        request_headers = cache.get("request_headers", None)
        request_content = cache.get("request_content", None)
        websocket_content = cache.get("websocket_content", None)
        websocket_type = cache.get("websocket_type", None)
        if websocket_type:
            msg = f"Request cache, addon: {addon_path}, keyword: {keyword}, method: {method}, url: {url}, status: {status}, headers: {request_headers}, websocket_type: {websocket_type}, websocket_content: {websocket_content}"
        else:
            msg = f"Request cache, addon: {addon_path}, keyword: {keyword}, method: {method}, url: {url}, status: {status}, headers: {request_headers}, request_content: {request_content}"
        cache_log.info(msg)
        if conf.scan.test:
            log.info(msg)
        else:
            cache_log.info(msg)



    async def __put_queue(self, data: dict, queue: asyncio.Queue):
        """将数据放入队列"""

        while True:
            queue_num = cache_queue.qsize() + param_queue.qsize() + path_queue.qsize() + email_queue.qsize() + \
                            vul_queue.qsize() + packet_queue.qsize() + cors_queue.qsize() + jsonp_queue.qsize()
            if queue_num < self.__max_data_queue_num:
                await queue.put((data, self.__addon_path))
                break
            else:
                await asyncio.sleep(0.1)


class RequestContextManager(_RequestContextManager):

    __slots__ = ()

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType],) -> None:
        if self._resp is not None:
            self._resp.release()


class WSRequestContextManager(_WSRequestContextManager):
    __slots__ = ()

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        if self._resp is not None:
            await self._resp.close()

