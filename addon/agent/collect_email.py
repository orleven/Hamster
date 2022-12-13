#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.core.g import email_queue
from lib.util.util import md5
from addon.agent import AgentAddon


class Addon(AgentAddon):
    """
    记录数据包中的email信息，并存入数据库。
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'CollectEmail'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "Email收集",
        self.level = VulLevel.NONE,
        self.vul_type = VulType.NONE,
        self.scopen = ""
        self.description = "将接口信息收集并进行记录。"
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

        self.block_length = 1024 * 4
        self.email_regex = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+)"
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
        self.black_mail_domian_list = [
            '.css', '.gif', '.jpg', '.png', '.ico', '.js', '.jpeg', '.gif', '.woff', '.ttf', 'github.com', "dcode.io",
            "github.com", "feross.org"
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

    def is_mail(self, email):
        """
        判断mail的后缀是否符合标准，排除由正则问题导致的误报
        :param mail:
        :return: bool
        """
        if '@' in email:
            mail_domian = email[email.index('@') + 1:]
            for black_domain in self.black_mail_domian_list:
                if black_domain in mail_domian:
                    return False
            if email[-1] == '.':
                return False
            if '.' in mail_domian:
                suffix = mail_domian[mail_domian.rindex('.') + 1:]
                if suffix.isdigit():
                    return False
            return True
        else:
            return False

    def email_infomation_check(self, text):
        """分块检测email"""

        res = []
        block_list = [text[i:i + self.block_length + 256] for i in range(0, len(text), self.block_length)]
        for block in block_list:
            try:
                block_str = re.sub(r'(\\u[\s\S]{4})', lambda x: x.group(1), block)
                email_list = re.findall(self.email_regex, block_str, re.IGNORECASE)
                for email in email_list:
                    if self.is_mail(email):
                        res.append(email)
            except:
                pass
        return res

    async def save_email(self, packet, email):
        """保存email信息"""

        if isinstance(packet, HTTPFlow):
            host = self.get_host(packet)
            port = self.get_port(packet)
            base_url = self.get_base_url(packet)
            url = self.get_url(packet)
            _md5 = md5('|'.join([base_url, email]))
            email_dic = dict(md5=_md5, host=host, port=port, url=url, email=email)
            await self.put_queue(email_dic, email_queue)

    async def prove(self, flow: HTTPFlow):
        if self.is_collect(flow):
            body = self.get_response_text(flow)
            if body:
                email_list = self.email_infomation_check(body)
                for email in email_list:
                    await self.save_email(flow, email)
