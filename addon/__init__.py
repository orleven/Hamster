#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import traceback
from lib.core.env import *
import re
import json
import asyncio
from copy import deepcopy
from urllib.parse import quote
from mitmproxy.tcp import TCPFlow
from mitmproxy.http import HTTPFlow
from aiohttp.client_reqrep import ClientResponse
from aiohttp.client_ws import ClientWebSocketResponse
from mitmproxy.net.http.headers import parse_content_type
from lib.core.g import conf
from lib.core.g import log
from lib.core.g import cache_queue
from lib.core.g import vul_queue
from lib.core.g import path_queue
from lib.core.g import param_queue
from lib.core.g import packet_queue
from lib.core.g import email_queue
from lib.core.g import jsonp_queue
from lib.core.g import cors_queue
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.core.enums import WebsocketType
from lib.core.enums import ScanMode
from lib.core.enums import ScanMatchPosition
from lib.core.enums import AddonType
from lib.core.enums import ScanMatchType
from lib.core.enums import AddonEnable
from lib.core.enums import ParameterType
from lib.util.util import md5
from lib.util.util import parse_url
from lib.util.util import get_time
from lib.util.util import get_time_str
from lib.util.util import random_md5
from lib.util.util import get_data_type
from lib.util.util import get_data_encode
from lib.util.util import get_data_encode_type
from lib.util.cipherutil import get_file_md5


class BaseAddon(object):
    """
    Addon 基础类
    """

    def __init__(self):
        # 脚本基本配置
        self.name = 'BaseAddon'
        self.enable = AddonEnable.ENABLE
        self.addon_type = AddonType.NONE
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.vul_name = ""
        self.description = ""
        self.scopen = ""
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

        # 脚本扫描配置
        self.max_data_queue_num = conf.basic.max_data_queue_num
        self.listen_domain = conf.basic.listen_domain
        self.scan_body_size_limit = conf.scan.scan_body_size_limit
        self.skip_scan_request_extensions = conf.scan.skip_scan_request_extensions
        self.skip_scan_response_content_types = conf.scan.skip_scan_response_content_types
        self.skip_scan_response_meida_types = conf.scan.skip_scan_response_meida_types
        self.scan_mode = conf.scan.scan_mode
        # self.is_save_request_body = conf.cache.is_save_request_body
        # self.is_save_response_body = conf.cache.is_save_response_body
        self.save_body_size_limit = conf.cache.save_body_size_limit
        self.dnslog_top_domain = conf.platform.dnslog_top_domain

        self.__basic_info()

        self.log = log

    def __basic_info(self):
        """脚本基础属性"""

        self.addon_absolute_path = sys.modules[self.__module__].__file__
        self.addon_path = self.addon_absolute_path[len(ROOT_PATH) + 1:]
        self.addon_file_name = os.path.basename(self.addon_path)
        self.addon_md5 = get_file_md5(self.addon_absolute_path)
        statinfo = os.stat(self.addon_absolute_path)
        self.file_create_time = get_time_str(get_time(statinfo.st_ctime))
        self.file_update_time = get_time_str(get_time(statinfo.st_ctime))

    def info(self):
        """获取脚本信息"""
        return {
            "addon_md5": self.addon_md5,
            "addon_name": self.name,
            "addon_type": self.addon_type,
            "addon_file_name": self.addon_file_name,
            "addon_path": self.addon_path,
            "file_create_time": self.file_create_time,
            "file_update_time": self.file_update_time,
            "vul_name": self.vul_name,
            "level": self.level,
            "vul_type": self.vul_type,
            "description": self.description,
            "scopen": self.scopen,
            "impact": self.impact,
            "suggestions": self.suggestions,
            "enable": self.enable,
            "mark": self.mark,
        }

    def request(self, flow):
        """对数据包的request部分进行注入修改，support、server使用"""

    def response(self, flow):
        """对数据包的response部分进行注入修改，support、server使用"""

    def websocket_message(self, flow):
        """对数据包的websocket部分进行注入修改，support、server使用"""

    # def load(self, loader):
    #     """首次加载插件时调用。此事件接收一个 Loader 对象，该对象包含用于添加选项和命令的方法。此方法是插件配置自身的地方。"""
    #
    #     default_setting = []
    #
    #     if loader:
    #         loader.add_option(
    #             name="default",
    #             typespec=str,
    #             default=json.dumps(default_setting),
    #             help="Add default setting",
    #         )

    # def configure(self, updated):
    #     """配置更改时调用。更新的参数是一个类似集合的对象，包含所有已更改选项的键。此事件在启动期间调用更新集中的所有选项。"""
    #
    #     if self.name in updated:
    #         for option_key, option_value in ctx.options.items():
    #             if option_key == self.name:
    #                 pass

    def __is_scan_time(self, scan_time):
        """判断是否在时间名单中"""

        start_time = scan_time.get("start_time", "")
        end_time = scan_time.get("end_time", "")
        now_time = get_time_str(fmt="%H:%M:%S")

        if start_time < now_time < end_time:
            return True, start_time, end_time
        else:
            return False, start_time, end_time

    def is_time_request(self, flow):
        """是否时间数据包。"""

        res = self.__is_scan_list(flow, conf.scan.scan_time, time_flag=True)
        if isinstance(res, tuple):
            return res
        else:
            return res, None, None

    def is_time_response(self, flow):
        """是否时间数据包。"""

        res = self.__is_scan_list(flow, conf.scan.scan_time, time_flag=True)
        if isinstance(res, tuple):
            return res
        else:
            return res, None, None

    def is_time_to_client(self, flow):
        """是否时间数据包。"""

        res = self.__is_scan_list(flow, conf.scan.scan_time, time_flag=True)
        if isinstance(res, tuple):
            return res
        else:
            return res, None, None

    def is_time_from_client(self, flow):
        """是否时间数据包。"""

        res = self.__is_scan_list(flow, conf.scan.scan_time, time_flag=True)
        if isinstance(res, tuple):
            return res
        else:
            return res, None, None

    def is_scan_request(self, flow):
        """是否跳过数据包，不进行扫描。"""

        extension = self.get_extension(flow)
        request_content_length = self.get_content_length(flow.request.headers)

        if not self.__is_scan_list(flow, conf.scan.scan_white):
            return False

        if self.__is_scan_list(flow, conf.scan.scan_black):
            return False

        if request_content_length > int(self.scan_body_size_limit):
            return False

        if extension in self.skip_scan_request_extensions:
            return False

        return True

    def is_scan_response(self, flow):
        """是否跳过数据包，不进行扫描。"""

        if not self.__is_scan_list(flow, conf.scan.scan_white):
            return False

        if self.__is_scan_list(flow, conf.scan.scan_black):
            return False

        response_content_length = self.get_content_length(flow.response.headers)
        if response_content_length > int(self.scan_body_size_limit):
            return False

        content_type = self.get_response_content_type(flow)
        if content_type and content_type in self.skip_scan_response_content_types:
            return False

        mime_type = content_type.split('/')[:1]
        if mime_type and mime_type[0] in self.skip_scan_response_meida_types:
            return False

        extension = self.get_extension(flow)
        if extension in self.skip_scan_request_extensions:
            return False

        return True

    def is_scan_to_client(self, flow):
        """websocket 是否跳过数据包，不进行扫描。"""


        if not self.__is_scan_list(flow, conf.scan.scan_white):
            return False

        if self.__is_scan_list(flow, conf.scan.scan_black):
            return False

        last_message = self.get_websocket_last_message(flow)
        if last_message and last_message.from_client:
            return False

        websocket_message_content_length = 0
        for message in self.get_websocket_messages(flow):
            websocket_message_content_length += len(message.content)

        if websocket_message_content_length > int(self.scan_body_size_limit):
            return False

        return True

    def is_scan_from_client(self, flow):
        """websocket 是否跳过数据包，不进行扫描。"""


        if not self.__is_scan_list(flow, conf.scan.scan_white):
            return False

        if self.__is_scan_list(flow, conf.scan.scan_black):
            return False

        last_message = self.get_websocket_last_message(flow)
        if last_message and not last_message.from_client:
            return False

        websocket_message_content_length = 0
        for message in self.get_websocket_messages(flow):
            websocket_message_content_length += len(message.content)

        if websocket_message_content_length > int(self.scan_body_size_limit):
            return False

        return True

    def __is_scan_list(self, flow, scan_list, time_flag=False):
        """
        判断是否在扫描名单中，timek_flag为true时，开启时间判断
        """

        host = self.get_host(flow)

        if host == self.listen_domain:
            return True

        if self.dnslog_top_domain in host:
            return True

        if scan_list:
            for scan in scan_list:
                flag = False
                match_position = scan.get("match_position", "")
                match_type = scan.get("match_type", "")
                value = scan.get("value", "")

                if match_position == ScanMatchPosition.HOST:
                    target = host

                elif match_position == ScanMatchPosition.URL:
                    target = self.get_url(flow)

                elif match_position == ScanMatchPosition.PATH:
                    target = self.get_path_no_query(flow)

                elif match_position == ScanMatchPosition.QUERY:
                    target = self.get_query(flow)

                elif match_position == ScanMatchPosition.METHOD:
                    target = self.get_method(flow)

                elif match_position == ScanMatchPosition.RESPONSE_BODY:
                    target = self.get_response_text(flow)

                elif match_position == ScanMatchPosition.STATUS:
                    target = str(self.get_status(flow))

                elif match_position == ScanMatchPosition.RESPONSE_HEADERS:
                    target = json.dumps(self.get_response_headers(flow))

                else:
                    target = None

                if target is not None:

                    if isinstance(target, bytes):
                        target = target.decode('utf-8')

                    elif isinstance(target, int):
                        target = str(target)

                    if match_type == ScanMatchType.EQUAL:
                        if value == target:
                            flag = True

                    elif match_type == ScanMatchType.IN:
                        if value in target:
                            flag = True

                    elif match_type == ScanMatchType.REGEX:
                        if re.search(value, target, re.M | re.I):
                            flag = True

                # 匹配到后再根据time表进行匹配
                if flag:
                    if time_flag:
                        return self.__is_scan_time(scan)
                    else:
                        return True

        return False

    @staticmethod
    def get_method(flow: HTTPFlow):
        """获取method"""

        return flow.request.method

    @staticmethod
    def get_scheme(flow: HTTPFlow):
        """获取scheme"""

        return flow.request.scheme

    @staticmethod
    def get_url(flow: HTTPFlow):
        """获取URL"""

        return flow.request.url

    @staticmethod
    def get_url_no_query(flow: HTTPFlow):
        """获取获取不带参数的URL，暂不处理 http://xxx/xxx;sessionid=xxxx 类型url，防止与http://xxx/;/../xxx url类混淆"""

        url = flow.request.url
        if url.startswith("://"):
            flow.request.url = flow.request.scheme + url
            url = flow.request.url

        if '?' in url:
            return url[:url.index('?')]
        # elif ';' in flow.request.path:
        #     return flow.request.url[:flow.request.url.index(';')]
        else:
            return url

    @staticmethod
    def get_base_url(flow: HTTPFlow):
        """获取基本URL地址"""

        if flow.request.scheme == 'http' and flow.request.port == 80:
            return flow.request.scheme + '://' + flow.request.host + '/'

        elif flow.request.scheme == 'https' and flow.request.port == 443:
            return flow.request.scheme + '://' + flow.request.host + '/'

        else:
            if flow.request.port == 443 or flow.request.port == 8443:
                flow.request.scheme = "https"
            else:
                flow.request.scheme = 'http'

        return flow.request.scheme + '://' + flow.request.host + ':' + str(flow.request.port) + '/'

    @staticmethod
    def get_host(flow: HTTPFlow):
        """获取host"""

        return flow.request.host

    @staticmethod
    def get_port(flow: HTTPFlow):
        """获取port"""

        return flow.request.port


    @staticmethod
    def get_status(flow: HTTPFlow):
        """获取status"""

        return flow.response.status_code

    @staticmethod
    def get_request_content(flow: HTTPFlow):
        """获取request content"""

        try:
            return flow.request.content
        except:
            return b''

    @staticmethod
    def get_response_content(flow: HTTPFlow):
        """获取response content"""

        try:
            return flow.response.content
        except:
            return b''

    @staticmethod
    def set_response_content(flow: HTTPFlow, data: bytes):
        """获取response content"""

        flow.response.content = data
        return flow

    @staticmethod
    def set_request_headers(flow: HTTPFlow, headers: dict):
        """获取request headers"""

        for key, value in headers.items():
            flow.request.headers[key] = value
        for key, value in flow.request.headers.items():
            if key not in headers.keys() and key != 'Content-Length':
                flow.request.headers.pop(key)
        return flow

    @staticmethod
    def set_request_path(flow: HTTPFlow, path: str):
        """获取request headers"""

        flow.request.path = path
        return flow

    @staticmethod
    def set_request_content(flow: HTTPFlow, data: bytes):
        """获取request content"""

        flow.request.content = data
        return flow

    @staticmethod
    def set_request_body(flow: HTTPFlow, body: str):
        """获取request body"""

        flow.request.body = body
        return flow

    @staticmethod
    def get_path_no_query(flow: HTTPFlow):
        """获取不带参数的Path"""

        base_url = BaseAddon.get_base_url(flow)
        url_no_query = BaseAddon.get_url_no_query(flow)
        path_no_query = url_no_query[len(base_url)-1:]
        return path_no_query

    @staticmethod
    def get_path_component(flow: HTTPFlow):
        """获取path并按斜杠分割"""

        return list(flow.request.path_components)

    @staticmethod
    def get_path_file(flow: HTTPFlow):
        """获取接口名称"""

        path = BaseAddon.get_path_no_query(flow)
        return path[path.rindex('/') + 1:]

    @staticmethod
    def get_path_dir(flow: HTTPFlow):
        """获取接口的目录"""

        path = BaseAddon.get_path_no_query(flow)
        return path[:path.rindex('/') + 1]

    @staticmethod
    def get_query(flow: HTTPFlow):
        """获取query，暂不处理 http://xxx/xxx;sessionid=xxxx 类型url，防止与http://xxx/;/../xxx url类混淆"""

        if '?' in flow.request.path:
            return flow.request.path[flow.request.path.index('?') + 1:]
        # elif ';' in flow.request.path:
        #     return flow.request.path[flow.request.path.index(';') + 1:]
        else:
            return ''

    @staticmethod
    def get_extension(flow: HTTPFlow):
        """获取后缀"""

        if not flow.request.path_components:
            return ''
        else:
            end_path = flow.request.path_components[-1:][0]
            split_ext = end_path.split('.')
            if not split_ext or len(split_ext) == 1:
                return ''
            else:
                return split_ext[-1:][0][:32]

    @staticmethod
    def get_websocket_message_by_index(flow: HTTPFlow, index=-1):
        """获取 websocket last message"""
        messages = BaseAddon.get_websocket_messages(flow)
        if len(messages) > 0:
            return messages[index]
        else:
            return None

    @staticmethod
    def get_websocket_last_message(flow: HTTPFlow):
        """获取 websocket last message"""
        return BaseAddon.get_websocket_message_by_index(flow, -1)

    @staticmethod
    def set_websocket_last_message(flow: HTTPFlow, message):
        """设置 websocket last message"""

        if flow.websocket and isinstance(flow.websocket.messages, list):
            if len(flow.websocket.messages) == 0:
                flow.websocket.messages[-1] = message
        return flow


    @staticmethod
    def get_request_cookies(flow: HTTPFlow):
        """解析request_cookies并返回"""

        res_cookies = {}
        for key, value in flow.request.cookies.items():
            res_cookies[key] = value
        return res_cookies

    @staticmethod
    def get_request_headers(flow: HTTPFlow, flag: bool = True):
        """
        解析request_headers并返回
        :param flow: Flow数据流
        :param flag: 是否清除Content-Length
        :return:
        """

        res_headers = {}
        for key, value in flow.request.headers.items():
            if key == 'Cookie':
                cookies = {}
                for cookie_key, cookie_value in flow.request.cookies.items():
                    cookies[cookie_key] = cookie_value
                res_headers['Cookie'] = cookies
            else:
                res_headers[key] = value
        if flag:
            if 'Content-Length' in res_headers.keys():
                res_headers.pop("Content-Length")
        return res_headers

    @staticmethod
    def get_response_headers(flow: HTTPFlow):
        """解析response_headers并返回"""

        res_headers = {}
        for key, value in flow.response.headers.items():
            res_headers[key] = value

        return res_headers

    @staticmethod
    def get_content_type(headers):
        """获取Content-Type"""

        return headers.get('Content-Type', None)

    @staticmethod
    def get_request_content_type(flow: HTTPFlow):
        """获取request的Content-Type"""

        if not flow.request.headers.get('Content-Type', None):
            return ''

        return flow.request.headers.get('Content-Type').split(';')[:1][0]

    @staticmethod
    def get_response_content_type(flow: HTTPFlow):
        """获取response的Content-Type"""

        if not flow.response.headers.get('Content-Type', None):
            return ''

        return flow.response.headers.get('Content-Type').split(';')[:1][0]

    @staticmethod
    def get_content_length(headers):
        """获取Content-Length"""

        return int(headers.get('Content-Length', 0))

    @staticmethod
    def get_request_content_length(flow: HTTPFlow):
        """获取request的Content-Length"""

        return int(flow.request.headers.get('Content-Length', 0))

    @staticmethod
    def get_response_content_length(flow: HTTPFlow):
        """获取response的Content-Length"""

        return int(flow.response.headers.get('Content-Length', 0))

    @staticmethod
    def get_response_media_type(flow: HTTPFlow):
        """获取media_type"""

        content_type = BaseAddon.get_response_content_type(flow)
        if content_type and content_type != '':
            http_mime_type = content_type.split('/')[0]
            return http_mime_type
        else:
            return ''

    @staticmethod
    def get_response_text(flow: HTTPFlow):
        """获取response_text"""

        try:
            body = flow.response.get_content()
            body = body.decode('utf-8')
            try:
                body = body.encode('latin-1').decode('unicode_escape')
            except:
                pass
        except:
            return None
        else:
            return body

    @staticmethod
    def get_websocket_messages(flow: HTTPFlow, list_str_flag=False):
        """获取websocket messages"""

        if flow.websocket:
            if not list_str_flag:
                return flow.websocket.messages
            else:
                temp = []
                for message in flow.websocket.messages:
                    temp.append({"is_text": message.is_text, "from_client": message.from_client, "content": message.content.decode('utf-8')})
                return json.dumps(temp)
        return None

    @staticmethod
    def get_websocket_type(flow: HTTPFlow):
        """获取websocket messages"""
        if flow.websocket and len(flow.websocket.messages) > 0:
            last_message = flow.websocket.messages[-1]
            if last_message.is_text:
                return WebsocketType.TEXT
            else:
                return WebsocketType.BINARY
        return WebsocketType.BINARY

    @staticmethod
    def multipart_encode(content_type, content_list):
        """
        生成multipart数据
        :param content_type: request headers 中的 content-type
        :param content_list: [(key, value, filename, current_content_type)]
        :return:
        """

        ct = parse_content_type(content_type)
        if ct is not None:
            try:
                boundary = ct[2]["boundary"].encode("ascii")
                boundary = quote(boundary)
            except (KeyError, UnicodeError):
                return b""
            hdrs = []
            for key, value, filename, current_content_type in content_list:
                if key:
                    if not isinstance(key, bytes):
                        key = str(key).encode('utf-8')

                    if not isinstance(value, bytes):
                        value = str(value).encode('utf-8')

                    if not isinstance(filename, bytes):
                        filename = str(filename).encode('utf-8')

                    if not isinstance(current_content_type, bytes):
                        current_content_type = str(current_content_type).encode('utf-8')

                    hdrs.append(b"--%b" % boundary.encode('utf-8'))
                    if filename:
                        disposition = b'form-data; name="%b"; filename="%b"' % (key, filename)
                    else:
                        disposition = b'form-data; name="%b"' % key
                    hdrs.append(b"Content-Disposition: %b" % disposition)

                    if current_content_type:
                        hdrs.append(b"Content-Type: %b" % current_content_type)
                    hdrs.append(b'')
                    hdrs.append(value)
                if value is not None:
                    if re.search(rb"^--%b$" % re.escape(boundary.encode('utf-8')), value):
                        raise ValueError(b"boundary found in encoded string")

            hdrs.append(b"--%b--\r\n" % boundary.encode('utf-8'))
            temp = b"\r\n".join(hdrs)
            return temp

    @staticmethod
    def multipart_decode(content_type, content: bytes):
        """
        解析multipart数据
        :param content_type:
        :param content:
        :return: [(key, value, filename, current_content_type)]
        """

        content_list = []
        if content_type:
            ct = parse_content_type(content_type)
            if not ct:
                return content_list
            try:
                boundary = ct[2]["boundary"].encode("ascii")
            except (KeyError, UnicodeError):
                return content_list

            r_key = re.compile(br'\bname="([^"]+)"')
            r_filename = re.compile(br'\bfilename="([^"]+)"')
            r_content_type = re.compile(br'\bContent-Type\: ([^"]+)')
            if content is not None:
                for child_content in content.split(b"--" + boundary):
                    parts = child_content.split(b'\r\n')
                    if len(parts) > 1 and parts[0][0:2] != b"--":
                        key_match = r_key.search(parts[1])
                        if key_match:
                            key = key_match.group(1)
                        else:
                            return content_list
                        filename_match = r_filename.search(parts[1])
                        if filename_match:
                            filename = filename_match.group(1)
                        else:
                            filename = None
                        content_type_match = r_content_type.search(parts[2])
                        if content_type_match:
                            current_content_type = content_type_match.group(1)
                        else:
                            current_content_type = None
                        value = b"\r\r".join(parts[3 + parts[2:].index(b""):-1])

                        # bytes 解码
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8')
                            except:
                                pass
                        content_list.append((key, value, filename, current_content_type))
        return content_list

    @staticmethod
    def get_request_boundary(flow: HTTPFlow):
        """获取multipart数据的boundary"""

        content_type = flow.request.headers.get('Content-Type', '')
        if 'boundary=' in content_type:
            boundary = content_type[content_type.rindex('boundary=') + 9:]
        else:
            boundary = None
        return boundary

    @staticmethod
    def parser_child_parameter_by_content(content):
        """解析子类参数（迭代）"""

        parameter_dic = {
            "index": random_md5(), "encode_type": [], "equal_char": False,
            "name": None, "value": None, "type": None,
            "content_type": None, "filename": None,
        }
        child_parameter_list = []
        if content is not None:
            if isinstance(content, bool):
                parameter_dic["value"] = content
                parameter_dic["type"] = ParameterType.BOOLEAN

            elif isinstance(content, bytes):
                parameter_dic["value"] = content
                parameter_dic["type"] = ParameterType.BYTES

            elif isinstance(content, int):
                parameter_dic["value"] = content
                parameter_dic["type"] = ParameterType.INT

            elif isinstance(content, float):
                parameter_dic["value"] = content
                parameter_dic["type"] = ParameterType.FLOAT

            elif isinstance(content, list):
                for sub_content in content:
                    child_parameter_dic = BaseAddon.parser_child_parameter_by_content(sub_content)
                    child_parameter_list.append(child_parameter_dic)
                parameter_dic["value"] = child_parameter_list
                parameter_dic["type"] = ParameterType.LIST

            elif isinstance(content, dict):
                for key, value in content.items():
                    child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                    child_parameter_dic["name"] = key
                    child_parameter_list.append(child_parameter_dic)
                parameter_dic["value"] = child_parameter_list
                parameter_dic["type"] = ParameterType.DICT

            # 字符串处理
            else:
                content, parameter_encode_type = get_data_encode_type(content)
                parameter_dic["encode_type"] = parameter_encode_type

                content, parameter_type = get_data_type(content)
                if parameter_type is None:
                    parameter_dic["type"] = ParameterType.STRING

                # json 处理
                if parameter_type in [ParameterType.JSON]:
                    if isinstance(content, dict):
                        parameter_dic["type"] = ParameterType.JSON
                        child_parameter_list = []
                        for key, value in content.items():
                            child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                            child_parameter_dic["name"] = key
                            child_parameter_list.append(child_parameter_dic)

                    elif isinstance(content, list):
                        parameter_dic["type"] = ParameterType.LIST
                        child_parameter_list = []
                        for value in content:
                            child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                            child_parameter_list.append(child_parameter_dic)

                    parameter_dic["value"] = child_parameter_list

                # 非json处理
                else:
                    if content is not None:
                        parameter_dic["type"] = ParameterType.STRING
                        parameter_dic["value"] = content
        else:
            parameter_dic["value"] = None
        return parameter_dic

    @staticmethod
    def parser_content_parameter(flow):
        """
        将参数转化为字典格式，便于后续扫描等操作
        :param flow:
        :return: parameter_dic: {"name": "参数名", "value": "参数值", "type": "参数类型", "filename": "formdata的filename值", "content_type": "formdata的content_type值", "equal_char": "是否带等号",  "encode_type": "编码类型"}
        """
        content = BaseAddon.get_request_content(flow)
        boundary = BaseAddon.get_request_boundary(flow)
        parameter_dic = BaseAddon.parser_parameter(content, boundary)
        return parameter_dic

    @staticmethod
    def parser_query_parameter(flow):
        """
        将参数转化为字典格式，便于后续扫描等操作
        :param flow:
        :return: parameter_list: [{"name": "参数名", "value": "参数值", "type": "参数类型", "filename": "formdata的filename值", "content_type": "formdata的content_type值", "equal_char": "是否带等号",  "encode_type": "编码类型"}]
        """
        query = BaseAddon.get_query(flow)
        parameter_list = BaseAddon.parser_parameter(query)
        return parameter_list

    @staticmethod
    def create_child_parameter(child_parameter_name, parameter_value, child_parameter_type=ParameterType.STRING,
                               child_parameter_encode_type=None, child_parameter_equal_char=True, child_parameter_filename=None,
                                child_parameter_content_type=None):
        """
        :param child_parameter_name: 参数名
        :param parameter_value: 参数值
        :param child_parameter_type: 参数类型，一般为ParameterType.STRING
        :param child_parameter_encode_type: 参数编码，目前支持自动urlcode编码/解码, 数组类型
        :param child_parameter_equal_char: value为空时是否带等号， 不带则是 xxx, 带则是 xxx=
        :param child_parameter_filename: 适用于formdata类型参数的filename
        :param child_parameter_content_type: 适用于formdata类型参数的content_type
        :return:
        """

        if child_parameter_encode_type is None:
            child_parameter_encode_type = []

        temp_sub_parameter_dic = {
            'name': child_parameter_name,  # 参数名
            'value': parameter_value,  # 参数值
            'type': child_parameter_type,  # 参数类型，一般为ParameterType.STRING
            'encode_type': child_parameter_encode_type,  # 参数编码，目前支持自动urlcode编码/解码
            'filename': child_parameter_filename,  # 适用于formdata类型参数的filename
            'index': random_md5(),  # 参数索引， 随机md即可
            'content_type': child_parameter_content_type,  # 适用于formdata类型参数的content_type
            'equal_char': child_parameter_equal_char  # value为空时是否带等号， 不带则是 xxx, 带则是 xxx=
        }
        return temp_sub_parameter_dic


    @staticmethod
    def parser_parameter(source_content, boundary=None):
        parameter_dic = {
            "index": random_md5(), "encode_type": [], "equal_char": False,
            "name": None, "value": None, "type": None,
            "content_type": None, "filename": None,
        }
        # boundary 格式
        if boundary:
            multipart_list = BaseAddon.multipart_decode(f'multipart/form-data; boundary={boundary}', source_content)
            child_parameter_list = []
            for key, value, filename, content_type in multipart_list:
                child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                child_parameter_dic["name"] = key
                child_parameter_dic["filename"] = filename
                child_parameter_dic["content_type"] = content_type
                if filename:
                    child_parameter_dic["type"] = ParameterType.FILE
                child_parameter_list.append(child_parameter_dic)
            parameter_dic["value"] = child_parameter_list
            parameter_dic["type"] = ParameterType.FORMDATA

        else:
            # bytes 先解码
            if isinstance(source_content, bytes):
                try:
                    source_content = source_content.decode('utf-8')
                except:
                    parameter_dic["type"] = ParameterType.BYTES
                    parameter_dic["value"] = source_content
                    return parameter_dic

            # 解析参数是否是json
            content, parameter_encode_type = get_data_encode_type(source_content)
            parameter_dic["encode_type"] = parameter_encode_type

            content, parameter_type = get_data_type(content)
            if parameter_type is None:
                parameter_dic["type"] = ParameterType.STRING

            # json 处理
            if parameter_type in [ParameterType.JSON, ParameterType.DICT, ParameterType.LIST]:
                child_parameter_list = []

                if isinstance(content, dict):
                    parameter_dic["type"] = ParameterType.JSON
                    for key, value in content.items():
                        child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                        child_parameter_dic["name"] = key
                        child_parameter_list.append(child_parameter_dic)

                elif isinstance(content, list):
                    parameter_dic["type"] = ParameterType.LIST
                    for value in content:
                        child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                        child_parameter_list.append(child_parameter_dic)

                parameter_dic["value"] = child_parameter_list

            # 非json处理
            else:
                child_parameter_list = []
                parameter_dic["type"] = ParameterType.PARAMETER
                if content is not None and content != '':
                    for item_str in content.split('&'):
                        if '=' in item_str:
                            key = item_str[0: item_str.index('=')]
                            value = item_str[item_str.index('=') + 1:]
                            child_parameter_dic = BaseAddon.parser_child_parameter_by_content(value)
                            child_parameter_dic["name"] = key
                            child_parameter_dic["equal_char"] = True
                            child_parameter_list.append(child_parameter_dic)
                        else:
                            key = None
                            value = item_str
                            child_parameter_dic = {
                                "name": key, "value": value, "type": parameter_type, "index": random_md5(),
                                "encode_type": parameter_encode_type, "filename": None,
                                "content_type": None, "equal_char": False
                            }
                            child_parameter_list.append(child_parameter_dic)

                    parameter_dic["value"] = child_parameter_list

        return parameter_dic

    @staticmethod
    def get_parameter_name_list_by_parameter_dic(parameter_dic):
        """获取参数名称列表"""

        parameter_name = parameter_dic.get("name", None)
        parameter_value = parameter_dic.get("value", None)
        parameter_name_list = []
        if parameter_value and isinstance(parameter_value, list):
            for item in parameter_value:
                parameter_name_list += BaseAddon.get_parameter_name_list_by_parameter_dic(item)
        if parameter_name:
            if isinstance(parameter_name, bytes):
                parameter_name = parameter_name.decode('utf-8')
            parameter_name_list.append(parameter_name)
        return parameter_name_list

    @staticmethod
    def get_parameter_name_list(flow: HTTPFlow):
        """解析flow参数，返回数组格式"""

        parameter_name_list = []

        query_dic = BaseAddon.parser_query_parameter(flow)
        parameter_name_list += BaseAddon.get_parameter_name_list_by_parameter_dic(query_dic)

        content_dic = BaseAddon.parser_content_parameter(flow)

        parameter_name_list += BaseAddon.get_parameter_name_list_by_parameter_dic(content_dic)

        parameter_name_list = sorted(list(set(parameter_name_list)))

        if flow.websocket:
            messages = BaseAddon.get_websocket_messages(flow)
            for message in messages:
                if message.from_client:
                    parameter_name_list += BaseAddon.get_parameter_name_list_by_parameter_dic(BaseAddon.parser_parameter(message.content))

        return parameter_name_list

    @staticmethod
    def generate_child_content(parameter_dic):
        """
        根据paramter_dic参数生成content, 用于迭代
        :param parameter_dic:
        :return:
        """
        if parameter_dic:
            if isinstance(parameter_dic, dict):
                parameter_type = parameter_dic.get("type", None)
                parameter_encode_type = parameter_dic.get("encode_type", [])
                parameter_value = parameter_dic.get("value", None)

                if parameter_value is not None:
                    if parameter_type == ParameterType.DICT:
                        content_dict = {}
                        for item in parameter_value:
                            if item and isinstance(item, dict):
                                child_parameter_name = item.get("name", None)
                                child_parameter_value = BaseAddon.generate_child_content(item)
                                content_dict[child_parameter_name] = child_parameter_value
                        content_parameter_value = content_dict

                    elif parameter_type == ParameterType.LIST:
                        content_list = []
                        for item in parameter_value:
                            if item:
                                child_parameter_value = BaseAddon.generate_child_content(item)
                                content_list.append(child_parameter_value)
                        content_parameter_value = content_list

                    elif parameter_type == ParameterType.JSON:
                        content_dict = {}
                        for item in parameter_value:
                            if item and isinstance(item, dict):
                                child_parameter_name = item.get("name", None)
                                child_parameter_value = BaseAddon.generate_child_content(item)
                                content_dict[child_parameter_name] = child_parameter_value
                        content_parameter_value = json.dumps(content_dict)

                    else:
                        content_parameter_value = parameter_value

                    content = get_data_encode(content_parameter_value, parameter_encode_type)
                else:
                    content = None

            elif isinstance(parameter_dic, list):
                content = []
                for item in parameter_dic:
                    if item:
                        content.append(BaseAddon.generate_child_content(item))

            else:
                content = parameter_dic

        else:
            content = None

        return content

    @staticmethod
    def generate_content(parameter_dic, boundary=None):
        """
        根据paramter_dic参数生成content
        :param parameter_dic: parameter_dic
        :param boundary: boundary
        :return: content: bytes类型
        """

        parameter_type = parameter_dic.get("type", None)
        parameter_value = parameter_dic.get("value", None)
        parameter_encode_type = parameter_dic.get("encode_type", [])

        if parameter_value is not None:
            if parameter_type == ParameterType.FORMDATA:
                if boundary is None:
                    boundary = "-" * 20 + random_md5(32)
                content_list = []
                content_type = "multipart/form-data; boundary=" + boundary
                for item in parameter_value:
                    if item and isinstance(item, dict):
                        child_parameter_type = item.get("type", None)
                        child_parameter_name = item.get("name", None)
                        child_parameter_value = item.get("value", None)
                        child_parameter_filename = item.get("filename", None)
                        child_parameter_content_type = item.get("content_type", None)
                        if child_parameter_type not in [ParameterType.FILE, ParameterType.BYTES]:
                            child_parameter_value = BaseAddon.generate_child_content(item)
                            if child_parameter_value is None:
                                child_parameter_value = ''
                            elif isinstance(child_parameter_value, dict) or isinstance(child_parameter_value, list):
                                child_parameter_value = json.dumps(child_parameter_value)
                            else:
                                child_parameter_value = str(child_parameter_value)
                            child_parameter_value = get_data_encode(child_parameter_value, parameter_encode_type)
                            child_parameter_value = child_parameter_value.encode('utf-8')
                        content_list.append((child_parameter_name, child_parameter_value, child_parameter_filename,
                                             child_parameter_content_type))
                content = BaseAddon.multipart_encode(content_type, content_list)

            elif parameter_type == ParameterType.PARAMETER:
                content_list = []
                for item in parameter_value:
                    if item and isinstance(item, dict):
                        child_parameter_name = item.get("name", None)
                        child_parameter_equal_char = item.get("equal_char", False)
                        if child_parameter_equal_char:
                            child_parameter_value = BaseAddon.generate_child_content(item)
                            if child_parameter_value is None:
                                child_parameter_value = ''
                            elif isinstance(child_parameter_value, dict) or isinstance(child_parameter_value, list):
                                child_parameter_value = json.dumps(child_parameter_value)
                            else:
                                child_parameter_value = str(child_parameter_value)
                            content_list.append(child_parameter_name + '=' + child_parameter_value)
                        else:
                            child_parameter_value = item.get("value", False)
                            content_list.append(child_parameter_value)

                content = '&'.join(content_list)
                content = get_data_encode(content, parameter_encode_type)

            elif parameter_type in [ParameterType.JSON, ParameterType.DICT]:
                content_dist = {}
                for item in parameter_value:
                    if item and isinstance(item, dict):
                        child_parameter_name = item.get("name", None)
                        child_parameter_value = BaseAddon.generate_child_content(item)
                        content_dist[child_parameter_name] = child_parameter_value
                content = json.dumps(content_dist)
                content = get_data_encode(content, parameter_encode_type)

            elif parameter_type == ParameterType.LIST:
                content_dict = []
                for item in parameter_value:
                    if item:
                        content_dict.append(BaseAddon.generate_child_content(item))
                content = json.dumps(content_dict)
                content = get_data_encode(content, parameter_encode_type)

            else:
                content = parameter_value
                content = get_data_encode(content, parameter_encode_type)

        else:
            content = b''

        if not isinstance(content, bytes):
            content = str(content)
            content = content.encode('utf-8')

        return content, boundary

    @staticmethod
    def update_parameter_by_index(parameter_dic, index, name, value, type=None, encode_type=None, equal_char=None,
                                  filename=None, content_type=None):
        """通过index 设置parameter"""

        if encode_type is None:
            encode_type = []

        parameter_index = parameter_dic.get("index", None)
        parameter_value = parameter_dic.get("value", None)
        if parameter_index == index:
            if value:
                if type and type in [ParameterType.STRING, ParameterType.INT, ParameterType.FLOAT,
                                     ParameterType.BOOLEAN, ParameterType.OTHER]:
                    parameter_dic["type"] = type
                    parameter_dic["value"] = value
                else:
                    parameter_dic = BaseAddon.parser_child_parameter_by_content(value)

            if name:
                parameter_dic["name"] = name

            if encode_type:
                parameter_dic["encode_type"] = encode_type

            if filename:
                parameter_dic["filename"] = filename

            if content_type:
                parameter_dic["content_type"] = content_type

            if equal_char:
                parameter_dic["equal_char"] = equal_char

            return parameter_dic

        if parameter_value and isinstance(parameter_value, list):
            for i in range(0, len(parameter_value)):
                parameter_value[i] = BaseAddon.update_parameter_by_index(parameter_value[i], index, name, value, type,
                                                                         encode_type, equal_char, filename,
                                                                         content_type)
            parameter_dic["value"] = parameter_value

        return parameter_dic

    @staticmethod
    async def generate_parameter_dic_by_function(source_parameter_dic, function=None):
        """
        通过导入函数生成修改后的parameter_dic, function函数样例格式如下:;
        async def generate_payload(self, text):;
            payloads = ["http://xx.dnslog.cn/", "gopher://xx.dnslog.cn/"];
            keyword = "xx.dnslog.cn";
            if isinstance(text, str) and text.startswith("http://"):;
                async for payload in payloads:;
                    yield payload, keyword;
        :param source_parameter_dic: 原parameter_dic
        :param function: 函数, 定义格式请看简洁
        :return: 生成修改后的parameter_dic
        """

        for child_parameter_dic in BaseAddon.get_parameter_list(source_parameter_dic):
            child_parameter_name = child_parameter_dic.get("name", None)
            child_parameter_type = child_parameter_dic.get("type", None)
            child_parameter_index = child_parameter_dic.get("index", None)
            child_parameter_filename = child_parameter_dic.get("filename", None)
            child_parameter_value = child_parameter_dic.get("value", None)
            child_parameter_encode_type = child_parameter_dic.get("encode_type", None)
            child_parameter_equal_char = child_parameter_dic.get("equal_char", None)
            child_parameter_content_type = child_parameter_dic.get("content_type", None)
            if child_parameter_type in [ParameterType.STRING, ParameterType.INT, ParameterType.FLOAT, ParameterType.BOOLEAN, ParameterType.OTHER,
                                        ParameterType.JSON, ParameterType.DICT, ParameterType.LIST, None]:
                async for function_result in function(child_parameter_value):
                    if function_result:
                        if isinstance(function_result, tuple):
                            parameter_value = function_result[0]
                            temp_parameter_dic = deepcopy(source_parameter_dic)
                            temp_parameter_dic = BaseAddon.update_parameter_by_index(temp_parameter_dic,
                                child_parameter_index, child_parameter_name, parameter_value, child_parameter_type,
                                child_parameter_encode_type, child_parameter_equal_char, child_parameter_filename,
                                child_parameter_content_type)
                            res_function_result = (temp_parameter_dic,)
                            if len(function_result) > 1:
                                res_function_result += function_result[1:]
                            yield res_function_result
                        else:
                            parameter_value = function_result
                            temp_parameter_dic = BaseAddon.update_parameter_by_index(temp_parameter_dic,
                                child_parameter_index, child_parameter_name, parameter_value, child_parameter_type,
                                child_parameter_encode_type, child_parameter_equal_char, child_parameter_filename,
                                child_parameter_content_type)
                            res_function_result = temp_parameter_dic
                            yield res_function_result

    @staticmethod
    async def generate_parameter_dic_by_name(source_parameter_dic, name, parameter_name=None, parameter_value=None,
                                             parameter_type=None,
                                             parameter_encode_type=None, parameter_equal_char=None,
                                             parameter_filename=None, parameter_content_type=None):
        """生成修改后的parameter_dic"""

        for child_parameter_dic in BaseAddon.get_parameter_list(source_parameter_dic):
            child_parameter_index = child_parameter_dic.get("index", None)
            child_parameter_name = child_parameter_dic.get("name", None)
            if child_parameter_name and child_parameter_name == name:
                temp_parameter_dic = deepcopy(source_parameter_dic)
                temp_parameter_dic = BaseAddon.update_parameter_by_index(temp_parameter_dic, child_parameter_index,
                    parameter_name, parameter_value, parameter_type, parameter_encode_type, parameter_equal_char,
                    parameter_filename, parameter_content_type)
                yield temp_parameter_dic

    @staticmethod
    async def generate_parameter_dic_by_type(source_parameter_dic, type, parameter_name=None, parameter_value=None,
                                             parameter_type=None,
                                             parameter_encode_type=None, parameter_equal_char=None,
                                             parameter_filename=None, parameter_content_type=None):
        """
        通过参数类型生成修改后的parameter_dic
        :param source_parameter_dic: 原parameter_dic
        :param type: 匹配到的参数类型
        :param parameter_name: 替换后的参数名
        :param parameter_value: 替换后的参数值
        :param parameter_type: 替换后的参数类型
        :return: 生成修改后的parameter_dic
        """

        if parameter_encode_type is None:
            parameter_encode_type = []

        for child_parameter_dic in BaseAddon.get_parameter_list(source_parameter_dic):
            child_parameter_index = child_parameter_dic.get("index", None)
            child_parameter_type = child_parameter_dic.get("type", None)
            if child_parameter_type == type:
                temp_parameter_dic = deepcopy(source_parameter_dic)
                temp_parameter_dic = BaseAddon.update_parameter_by_index(temp_parameter_dic, child_parameter_index,
                    parameter_name, parameter_value, parameter_type, parameter_encode_type, parameter_equal_char,
                    parameter_filename, parameter_content_type)
                yield temp_parameter_dic

    # def format_parameter_dic_by_value(source_parameter_dic, template_value=None, parameter_value=None):
    #     """格式化全部替换修改后的parameter_dic"""
    #
    #
    #     for child_parameter_dic in get_parameter_list(source_parameter_dic):
    #         child_parameter_index = child_parameter_dic.get("index", None)
    #         child_parameter_value = child_parameter_dic.get("value", None)
    #         if isinstance(child_parameter_value, str):
    #             temp_parameter_dic = deepcopy(source_parameter_dic)
    #             parameter_value = child_parameter_value.replace(template_value, parameter_value)
    #             setting_parameter_by_index(temp_parameter_dic, child_parameter_index, None, parameter_value, None)
    #     return temp_parameter_dic
    #

    @staticmethod
    def delete_parameter_dic_by_like_name(parameter_dic, name=None, flag=False):
        """通过参数名来模糊删除parameter_dic参数"""

        temp_parameter_value = parameter_dic.get("value", None)
        temp_parameter_name = parameter_dic.get("name", None)
        if temp_parameter_value and isinstance(temp_parameter_value, list):
            for i in range(0, len(temp_parameter_value)):
                if temp_parameter_value[i]:
                    sub_parameter_value = BaseAddon.delete_parameter_dic_by_like_name(temp_parameter_value[i], name, flag)
                    temp_parameter_value[i] = sub_parameter_value
            parameter_dic["value"] = temp_parameter_value
        if temp_parameter_name and name:
            if isinstance(temp_parameter_name, bytes):
                temp_parameter_name = temp_parameter_name.decode('utf-8')
            if name in temp_parameter_name:
                if flag:
                    parameter_dic = None
                    return parameter_dic
                else:
                    parameter_dic["value"] = None
                    parameter_dic["encode_type"] = []
        return parameter_dic

    @staticmethod
    def delete_parameter_dic_by_name(parameter_dic, name=None, flag=False):
        """通过参数名来删除parameter_dic参数"""

        temp_parameter_value = parameter_dic.get("value", None)
        temp_parameter_name = parameter_dic.get("name", None)
        if temp_parameter_value and isinstance(temp_parameter_value, list):
            for i in range(0, len(temp_parameter_value)):
                if temp_parameter_value[i]:
                    sub_parameter_value = BaseAddon.delete_parameter_dic_by_like_name(temp_parameter_value[i], name,
                                                                                      flag)
                    temp_parameter_value[i] = sub_parameter_value
            parameter_dic["value"] = temp_parameter_value
        if temp_parameter_name and name:
            if isinstance(temp_parameter_name, bytes):
                temp_parameter_name = temp_parameter_name.decode('utf-8')
            if name == temp_parameter_name:
                if flag:
                    parameter_dic = None
                    return parameter_dic
                else:
                    parameter_dic["value"] = None
                    parameter_dic["encode_type"] = []
        return parameter_dic

    @staticmethod
    def replace_parameter_dic_by_name(parameter_dic, name=None, parameter_name=None, parameter_value=None, parameter_type=None,
            parameter_filename=None, parameter_encode_type=None, parameter_content_type=None, parameter_equal_char=None):
        """通过参数名来修改parameter_dic参数"""

        if parameter_encode_type is None:
            parameter_encode_type = []

        temp_parameter_value = parameter_dic.get("value", None)
        temp_parameter_name = parameter_dic.get("name", None)
        if temp_parameter_value and isinstance(temp_parameter_value, list):
            for i in range(0, len(temp_parameter_value)):
                if temp_parameter_value[i]:
                    sub_parameter_value = BaseAddon.replace_parameter_dic_by_name(temp_parameter_value[i], name, parameter_name, parameter_value,
                        parameter_type, parameter_filename, parameter_encode_type, parameter_content_type, parameter_equal_char)
                    temp_parameter_value[i] = sub_parameter_value
            parameter_dic["value"] = temp_parameter_value

        if temp_parameter_name and name:
            if isinstance(temp_parameter_name, bytes):
                temp_parameter_name = temp_parameter_name.decode('utf-8')
            if name == temp_parameter_name:
                if parameter_name:
                    parameter_dic["name"] = parameter_name
                if parameter_value:
                    parameter_dic["value"] = parameter_value
                if parameter_type:
                    parameter_dic["type"] = parameter_type
                if parameter_filename:
                    parameter_dic["filename"] = parameter_filename
                if parameter_encode_type and len(parameter_encode_type) > 0:
                    parameter_dic["encode_type"] = parameter_encode_type
                if parameter_content_type:
                    parameter_dic["content_type"] = parameter_content_type
                if parameter_equal_char:
                    parameter_dic["parameter_equal_char"] = parameter_equal_char
        return parameter_dic

    @staticmethod
    def replace_parameter_dic_by_type(parameter_dic, type=None, parameter_name=None, parameter_value=None,
            parameter_type=None, parameter_filename=None, parameter_encode_type=None, parameter_content_type=None, parameter_equal_char=None):
        """通过参数类型来修改parameter_dic参数"""

        if parameter_encode_type is None:
            parameter_encode_type = []

        temp_parameter_value = parameter_dic.get("value", None)
        temp_parameter_type = parameter_dic.get("type", None)
        if temp_parameter_value and isinstance(temp_parameter_value, list):
            for i in range(0, len(temp_parameter_value)):
                if temp_parameter_value[i]:
                    sub_parameter_value = BaseAddon.replace_parameter_dic_by_type(temp_parameter_value[i], type,
                        parameter_name, parameter_value, parameter_type, parameter_filename, parameter_encode_type,
                        parameter_content_type, parameter_equal_char)
                    temp_parameter_value[i] = sub_parameter_value
            parameter_dic["value"] = temp_parameter_value

        if temp_parameter_type and type and type == temp_parameter_type:
            if parameter_name:
                parameter_dic["name"] = parameter_name
            if parameter_value:
                parameter_dic["value"] = parameter_value
            if parameter_type:
                parameter_dic["type"] = parameter_type
            if parameter_filename:
                parameter_dic["filename"] = parameter_filename
            if parameter_encode_type and len(parameter_encode_type) > 0:
                parameter_dic["encode_type"] = parameter_encode_type
            if parameter_content_type:
                parameter_dic["content_type"] = parameter_content_type
            if parameter_equal_char:
                parameter_dic["parameter_equal_char"] = parameter_equal_char
        return parameter_dic

    @staticmethod
    def format_parameter_dic_by_value(parameter_dic, template_value=None, parameter_value=None):
        """格式化参数名来修改parameter_dic参数"""

        temp_parameter_value = parameter_dic.get("value", None)
        if temp_parameter_value:
            if isinstance(temp_parameter_value, list):
                for i in range(0, len(temp_parameter_value)):
                    if temp_parameter_value[i]:
                        sub_parameter_value = BaseAddon.replace_parameter_dic_by_name(temp_parameter_value[i], None, None, parameter_value)
                        temp_parameter_value[i] = sub_parameter_value
                parameter_dic["value"] = temp_parameter_value

            elif isinstance(temp_parameter_value, str):
                parameter_value = temp_parameter_value.replace(template_value, parameter_value)
                parameter_dic["value"] = parameter_value

        return parameter_dic

    @staticmethod
    def get_parameter_list(parameter_dic):
        """获取所有参数列表"""

        parameter_name = parameter_dic.get("name", None)
        parameter_value = parameter_dic.get("value", None)
        parameter_type = parameter_dic.get("type", None)
        parameter_filename = parameter_dic.get("filename", None)
        parameter_encode_type = parameter_dic.get("encode_type", [])
        parameter_content_type = parameter_dic.get("content_type", None)
        parameter_index = parameter_dic.get("index", None)
        parameter_equal_char = parameter_dic.get("equal_char", None)
        parameter_list = []

        if parameter_value and isinstance(parameter_value, list):
            for item in parameter_value:
                parameter_list += BaseAddon.get_parameter_list(item)

        parameter_dic = {
            "name": parameter_name, "value": parameter_value, "type": parameter_type,
            "encode_type": parameter_encode_type, "filename": parameter_filename, "index": parameter_index,
            "content_type": parameter_content_type, "equal_char": parameter_equal_char
        }
        parameter_list.append(parameter_dic)
        return parameter_list

    @staticmethod
    def parser_header(headers, flag: bool = True):
        """解析headers并返回"""

        res_headers = {}
        for key, value in headers.items():
            res_headers[key] = value
        if flag:
            if 'Content-Length' in res_headers.keys():
                res_headers.pop("Content-Length")

        return res_headers

    @staticmethod
    def parser_aiohttp_response_packet(packet):
        """解析aiohttp response packet"""

        url = str(packet.url)
        scheme = packet.url.scheme
        method = packet.method
        host = packet.url.host
        port = packet.url.port
        response_major = str(packet.version.major)
        response_minor = str(packet.version.minor)
        request_http_version = f'HTTP/{response_major}.{response_minor}'
        request_content_length = BaseAddon.get_content_length(packet.request_info.headers)
        request_headers = BaseAddon.parser_header(packet.request_info.headers, False)
        if 'Proxy-Authorization' in request_headers.keys():
            request_headers.pop("Proxy-Authorization")
        request_headers = json.dumps(request_headers)
        response_headers = json.dumps(BaseAddon.parser_header(packet.headers, False))
        response_http_version = f'HTTP/{response_major}.{response_minor}'
        response_status_code = packet.status
        response_reason = packet.reason
        response_content_type = BaseAddon.get_content_type(packet.headers)
        response_content_length = BaseAddon.get_content_length(packet.headers)
        request_content = packet.request_content if hasattr(packet, "request_content") else None
        request_content = request_content
        response_content = packet.__dict__.get("response_content", b'')
        websocket_type = None
        websocket_content = None

        packet_dic = dict(
            scheme=scheme, method=method, host=host, port=port, url=url,
            request_headers=request_headers, request_content_length=request_content_length,
            request_content=request_content, response_headers=response_headers,
            response_http_version=response_http_version,
            response_content_length=response_content_length, websocket_type=websocket_type,
            request_http_version=request_http_version, websocket_content=websocket_content,
            response_status_code=response_status_code, response_content_type=response_content_type,
            response_reason=response_reason, response_content=response_content,
        )

        return packet_dic

    @staticmethod
    def parser_aiohttp_websocket_response_packet(packet):
        """解析aiohttp response websocket packet"""

        url = str(packet._response.url)
        scheme = packet._response.url.scheme
        method = packet._response.method
        host = packet._response.url.host
        port = packet._response.url.port
        response_major = str(packet._response.version.major)
        response_minor = str(packet._response.version.minor)
        request_http_version = f'HTTP/{response_major}.{response_minor}'
        request_content_length = None
        temp_headers = packet.request_info.headers if hasattr(packet, "request_info") else {}
        request_headers = BaseAddon.parser_header(packet.request_info.headers, False)
        if 'Proxy-Authorization' in request_headers.keys():
            request_headers.pop("Proxy-Authorization")
        request_headers = json.dumps(request_headers)
        response_headers = json.dumps(BaseAddon.parser_header(packet._response.headers, False))
        response_http_version = f'HTTP/{response_major}.{response_minor}'
        response_status_code = packet._response.status
        response_reason = packet._response.reason
        response_content_type = BaseAddon.get_content_type(packet._response.headers)
        response_content_length = None
        request_content = None
        response_content = None
        websocket_content = packet.websocket_content if hasattr(packet, "websocket_content") else None
        websocket_type = packet.websocket_type if hasattr(packet, "websocket_type") else None

        packet_dic = dict(
            scheme=scheme, method=method, host=host, port=port, url=url,
            request_headers=request_headers, request_content_length=request_content_length,
            request_content=request_content, response_headers=response_headers,
            response_http_version=response_http_version,
            response_content_length=response_content_length, websocket_type=websocket_type,
            request_http_version=request_http_version, websocket_content=websocket_content,
            response_status_code=response_status_code, response_content_type=response_content_type,
            response_reason=response_reason, response_content=response_content,
        )

        return packet_dic

    @staticmethod
    def parser_httpflow_packet(packet, more_detail_flag=False):
        """解析httpflow packet"""

        url = packet.request.url
        host = packet.request.host
        port = int(packet.request.port)
        scheme = packet.request.scheme
        method = packet.request.method
        request_http_version = packet.request.http_version
        request_headers = json.dumps(BaseAddon.parser_header(packet.request.headers, False))
        request_content_length = BaseAddon.get_content_length(packet.request.headers)
        response_headers = json.dumps(BaseAddon.parser_header(packet.response.headers, False))
        response_content_length = BaseAddon.get_content_length(packet.response.headers)
        response_status_code = int(packet.response.status_code)
        response_content_type = BaseAddon.get_response_content_type(packet)
        response_http_version = packet.response.http_version
        response_reason = packet.response.reason
        request_content = packet.request.content
        response_content = packet.response.content
        websocket_content = BaseAddon.get_websocket_messages(packet, True)
        websocket_content = websocket_content.encode("utf-8") if websocket_content else None
        websocket_type = BaseAddon.get_websocket_type(packet)

        packet_dic = dict(
            scheme=scheme, method=method, host=host, port=port, url=url,
            request_headers=request_headers, request_content_length=request_content_length,
            request_content=request_content, response_headers=response_headers,
            response_http_version=response_http_version,
            response_content_length=response_content_length, websocket_type=websocket_type,
            request_http_version=request_http_version, websocket_content=websocket_content,
            response_status_code=response_status_code, response_content_type=response_content_type,
            response_reason=response_reason, response_content=response_content,
        )

        if more_detail_flag:
            if packet.client_conn:
                client_conn_sni = packet.client_conn.sni
                client_conn_cipher_name = packet.client_conn.cipher
                client_conn_tls_version = packet.client_conn.tls_version
                client_conn_address = packet.client_conn.address[0] + ':' + str(
                    packet.client_conn.address[1]) if packet.client_conn.address else None
                client_conn_ip_address = packet.client_conn.peername[0] + ':' + str(
                    packet.client_conn.peername[1]) if packet.client_conn.peername else None
                client_conn_proxy_address = packet.client_conn.sockname[0] + ':' + str(
                    packet.client_conn.sockname[1]) if packet.client_conn.sockname else None
                packet_more_detail_dic = dict(
                    client_conn_sni=client_conn_sni, client_conn_cipher_name=client_conn_cipher_name,
                    client_conn_tls_version=client_conn_tls_version, client_conn_address=client_conn_address,
                    client_conn_ip_address=client_conn_ip_address, client_conn_proxy_address=client_conn_proxy_address,
                )
                packet_dic = dict(packet_dic, **packet_more_detail_dic)
            if packet.server_conn:
                server_conn_sni = packet.server_conn.sni
                server_conn_cipher_name = packet.server_conn.cipher
                server_conn_tls_version = packet.server_conn.tls_version
                server_conn_address = packet.server_conn.address[0] + ':' + str(
                    packet.server_conn.address[1]) if packet.server_conn.address else None
                server_conn_ip_address = packet.server_conn.peername[0] + ':' + str(
                    packet.server_conn.peername[1]) if packet.server_conn.peername else None
                server_conn_proxy_address = packet.server_conn.sockname[0] + ':' + str(
                    packet.server_conn.sockname[1]) if packet.server_conn.sockname else None
                packet_more_detail_dic = dict(
                    server_conn_sni=server_conn_sni, server_conn_cipher_name=server_conn_cipher_name,
                    server_conn_tls_version=server_conn_tls_version, server_conn_address=server_conn_address,
                    server_conn_ip_address=server_conn_ip_address,  server_conn_proxy_address=server_conn_proxy_address,
                )
                packet_dic = dict(packet_dic, **packet_more_detail_dic)
        return packet_dic

    @staticmethod
    def parser_aiohttp_dic_packet(packet):
        """解析解析aiohttp dic packet"""

        url = packet.get("url", None)
        method = packet.get("method", None)
        request_content = packet.get("request_content", None)
        request_content = request_content.encode(encoding="utf8") if request_content and isinstance(request_content, str) else request_content
        scheme, host, port = parse_url(url)
        request_headers = json.dumps(packet.get("headers", None))
        request_http_version = 'HTTP/1.1'
        request_content_length = len(request_content) if request_content else 0
        response_content_length = 0
        response_status_code = 0
        websocket_content = None  # 需要调试
        websocket_type = None  # 需要调试
        response_http_version = None
        response_headers = None
        response_reason = None
        response_content = None
        response_content_type = None
        packet_dic = dict(
            scheme=scheme, method=method, host=host, port=port, url=url,
            request_headers=request_headers, request_content_length=request_content_length,
            request_content=request_content, response_headers=response_headers,
            response_http_version=response_http_version,
            response_content_length=response_content_length, websocket_type=websocket_type,
            request_http_version=request_http_version, websocket_content=websocket_content,
            response_status_code=response_status_code, response_content_type=response_content_type,
            response_reason=response_reason, response_content=response_content,
        )
        return packet_dic


    @staticmethod
    def parser_tcpflow_packet(packet, more_detail_flag=False):
        """解析tcpflow packet， 暂未实现"""

        # packet_dic = dict(
        #     scheme=scheme, method=method, host=host, port=port, url=url,
        #     request_headers=request_headers, request_content_length=request_content_length,
        #     request_content=request_content, response_headers=response_headers,
        #     response_http_version=response_http_version,
        #     response_content_length=response_content_length, websocket_type=websocket_type,
        #     request_http_version=request_http_version, websocket_content=websocket_content,
        #     response_status_code=response_status_code, response_content_type=response_content_type,
        #     response_reason=response_reason, response_content=response_content,
        # )
        # return packet_dic
        return dict()

    @staticmethod
    async def parser_packet(packet, more_detail_flag=False):
        """解析packet"""

        try:
            if isinstance(packet, ClientResponse):
                response_content = await packet.read()
                packet.__dict__['response_content'] = response_content if response_content else b''
                packet_dic = BaseAddon.parser_aiohttp_response_packet(packet)
            elif isinstance(packet, ClientWebSocketResponse):
                packet_dic = BaseAddon.parser_aiohttp_websocket_response_packet(packet)
            elif isinstance(packet, HTTPFlow):
                packet_dic = BaseAddon.parser_httpflow_packet(packet, more_detail_flag)
            elif isinstance(packet, TCPFlow):
                packet_dic = BaseAddon.parser_tcpflow_packet(packet, more_detail_flag)
            elif isinstance(packet, dict):
                packet_dic = BaseAddon.parser_aiohttp_dic_packet(packet)
            else:
                log.error(f"Error parser packet, error: Error type.")
                return None

            request_content = packet_dic.get("request_content", None)
            packet_dic["request_content"] = request_content[:conf.scan.save_body_size_limit] if request_content else None
            response_content = packet_dic.get("response_content", None)
            packet_dic["response_content"] = response_content[:conf.scan.save_body_size_limit] if response_content else None
            websocket_content = packet_dic.get("websocket_content", None)
            packet_dic["websocket_content"] = websocket_content[:conf.scan.save_body_size_limit] if websocket_content else None
            packet_dic["update_time"] = get_time()


            return packet_dic
        except Exception as e:
            msg = str(e)
            traceback.print_exc()
            log.error(f"Error parser packet, error: {msg}")
            return None

    async def put_queue(self, data: dict, queue: asyncio.Queue):
        """将数据放入队列"""

        while True:
            queue_num = cache_queue.qsize() + param_queue.qsize() + path_queue.qsize() + email_queue.qsize() + \
                            vul_queue.qsize() + packet_queue.qsize() + cors_queue.qsize() + jsonp_queue.qsize()
            if queue_num < self.max_data_queue_num:
                await queue.put((data, self.addon_path))
                break
            else:
                await asyncio.sleep(0.1)


    # async def save_cache(self, keyword, packet):
    #     """保存扫描的缓存数据包"""
    #
    #     cache = await self.parser_packet(packet)
    #     if cache:
    #         cache["keyword"] = keyword
    #
    #         if self.is_save_request_body:
    #             cache["request_content"] = cache.get("request_content", b'')[:self.save_body_size_limit]
    #         else:
    #             cache["request_content"] = None
    #
    #         if self.is_save_response_body:
    #             cache["response_content"] = cache.get("response_content", b'')[:self.save_body_size_limit]
    #         else:
    #             cache["response_content"] = None
    #
    #         # 记录日志
    #         self.__print_cache_log(cache)
    #
    #         if self.is_save:
    #             await self.put_queue(cache, cache_queue)
    #
    # async def save_cache_by_none(self, keyword, method, url, headers, data=None):
    #     """保存扫描的缓存数据包"""
    #
    #     packet = {
    #         "method": method,
    #         "url": url,
    #         "headers": headers,
    #         "data": data,
    #     }
    #     await self.save_cache(keyword, packet)

    async def save_vul(self, packet, detail=None):
        """
        保存漏洞
        :param packet: 数据包， Flow或Response
        :param detail: 漏洞验证信息
        :return:
        """

        vul = await self.parser_packet(packet)
        if vul:
            vul["detail"] = detail[:1024] if detail else None
            vul["md5"] = md5('|'.join([vul.get('method'), vul.get('url'), self.addon_path]))
            vul["addon_path"] = self.addon_path
            await self.put_queue(vul, vul_queue)

    async def put_vul_queue(self, vul):
        await self.put_queue(vul, vul_queue)

    async def to_vul(self, packet, detail=None):
        """
        转化为漏洞
        :param packet: 数据包， Flow或Response
        :param detail: 漏洞验证信息
        :return:
        """

        vul = await self.parser_packet(packet)
        if vul:
            vul["detail"] = detail[:1024] if detail else None
            vul["md5"] = md5('|'.join([vul.get('method'), vul.get('url'), self.addon_path]))
            vul["addon_path"] = self.addon_path
            return vul
        return None

    async def get_dnslog_recode(self, domain=None):
        """请求dnslog recode"""

        if self.scan_mode == ScanMode.NOCACHE:
            from lib.core.api import get_dnslog_recode
            dnslog_list = await get_dnslog_recode(domain)
            if len(dnslog_list) > 0:
                return True
        return False