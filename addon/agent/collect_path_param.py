#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.core.g import path_queue
from lib.core.g import param_queue
from lib.util.util import md5
from addon.agent import AgentAddon


class Addon(AgentAddon):
    """
    记录数据包中的目录路径参数名信息，并存入数据库。
    select *,count(*) as new_count from dir where host like '%' || ? GROUP BY dir ORDER BY new_count DESC
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'CollectPathParam'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "接口信息收集"
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.scopen = ""
        self.description = "将接口信息收集并进行记录。"
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

        self.skip_collect_content_tpyes = [
            "text/css", "application/javascript", "application/x-javascript",
            "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
            "application/x-ms-wmd", "application/x-shockwave-flash", "image/x-cmu-raster",
            "image/x-ms-bmp", "image/x-portable-graymap", "image/x-portable-bitmap", "image/jpeg",
            "image/gif", "image/x-xwindowdump", "image/png", "image/vnd.microsoft.icon",
            "image/x-portable-pixmap", "image/x-xpixmap", "image/ief", "image/x-portable-anymap",
            "image/x-rgb", "image/x-xbitmap", "image/tiff", "video/mpeg", "video/x-sgi-movie",
            "video/mp4", "video/x-msvideo", "video/quicktim", "audio/mpeg", "audio/x-wav",
            "audio/x-aiff", "audio/basic", "audio/x-pn-realaudio", "application/font-woff"
        ]
        self.skip_collect_extensions = [
            "js", "css", "ico", "png", "jpg", "video", "audio", "ttf", "jpeg", "gif", "woff",
            "map", 'woff2', 'bin', 'wav', 'md', "mp3", "vue", "jpeg"
        ]
        self.skip_scan_media_types = [
            "image", "video", "audio"
        ]
        self.exclude_parameter = [
            "_t", "t"
        ]

    def is_collect(self, flow):
        """
        是否跳过数据包，不进行捕获。
        """

        extension = self.get_extension(flow)
        content_type = self.get_response_content_type(flow)

        if extension in self.skip_collect_extensions:
            return False

        if not content_type:
            return True

        if content_type in self.skip_collect_content_tpyes:
            return False

        http_mime_type = content_type.split('/')[:1]
        if http_mime_type:
            return False if http_mime_type[0] in self.skip_scan_media_types else True

        return True

    def is_collect_param(self, param):
        """
        是否跳过数据包，不进行捕获。
        """

        if param in self.exclude_parameter:
            return False

        # 总有些路径中会有奇怪的参数名，不做记录
        if "http:" in param or "http://" in param or len(param) >= 32:
            return False

        return True

    async def save_path(self, packet):
        """保存路径信息"""

        if isinstance(packet, HTTPFlow):
            host = self.get_host(packet)
            port = self.get_port(packet)
            url_no_query = self.get_url_no_query(packet)
            path = self.get_path_no_query(packet)
            url = self.get_url(packet)
            path_file = self.get_path_file(packet)
            path_dir = self.get_path_dir(packet)
            _md5 = md5('|'.join([url_no_query]))
            path_dic = dict(md5=_md5, host=host, port=port, url=url, path=path, dir=path_dir, file=path_file)
            await self.put_queue(path_dic, path_queue)

    async def save_param(self, packet, param):
        """保存参数信息"""

        if isinstance(packet, HTTPFlow):
            host = self.get_host(packet)
            port = self.get_port(packet)
            path = self.get_path_no_query(packet)
            base_url = self.get_base_url(packet)
            url = self.get_url(packet)
            _md5 = md5('|'.join([base_url, param]))
            param_dic = dict(md5=_md5, host=host, port=port, url=url, path=path, param=param)
            await self.put_queue(param_dic, param_queue)

    async def prove(self, flow: HTTPFlow):
        if self.is_collect(flow):
            # 保存path
            await self.save_path(flow)
            for param in self.get_parameter_name_list(flow):
                if self.is_collect_param(param):
                    # 保存param
                    await self.save_param(flow, param)
