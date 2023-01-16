#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon

class Addon(AgentAddon):
    """
    返回包的敏感信息检测，主要包括手机号、身份证、邮箱。
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'SensitiveInformation'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "敏感信息泄露"
        self.level = VulLevel.LOWER
        self.vul_type = VulType.INFO
        self.description = "敏感信息泄露，由于错误处理系统数据信息或系统存在安全漏洞，导致敏感信息的泄露。"
        self.scopen = ""
        self.impact = "1. 敏感信息泄露。 2. 攻击者可以收集泄露的敏感信息并进行整合用以结合其他安全风险及漏洞进行进一步的攻击。"
        self.suggestions = "1. 对敏感信息进行脱敏处理。"
        self.mark = ""

        self.black_ext_list = ['jpg', 'png', 'pdf', 'png', 'docx', 'doc', 'jpeg', 'xlsx', 'csv']
        self.black_media_type_list = ["image", "video", "audio"]
        self.black_content_type = ["application/font-woff"]
        self.black_mail_domian_list = [
            '.css', '.gif', '.jpg', '.png', '.ico', '.js', '.jpeg', '.gif', '.woff', '.ttf', 'github.com', "dcode.io",
            "github.com", "feross.org"
        ]
        self.black_password_list = [
            "sso", "function", "this", "that", "define", "storage", "instruction", "__",
            "true", "false", "text", "hidden", "null", "before", "code", "input", "async", 'change',
            "pend", "this", "hide", "after", "new", "object", "string", "hover", "reset", "return", "void", "escape",
            "crypt"
        ]
        self.black_token_list = [
            "sso", "function", "this", "that", "define", "storage", "instruction",
            "true", "false", "text", "hidden", "null", "before", "code", "input", "async", 'change',
            "pend", "this", "hide", "after", "new", "object", "string", "hover", "reset", "return", "void", "escape",
            "crypt"
        ]
        self.regex_map = {
            # "mail": r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+)",
            # "host": r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:[0-9]{0,5}]{0,1})",
            # "ip": r"((?:(?:2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(?:2[0-4]\d|25[0-5]|[01]?\d\d?))",
            "password": r"password\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([a-zA-Z0-9\!\@\#\$\^]{3,32})\\?\"?'?",
            "pwd": r"pwd\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([a-zA-Z0-9\!\@\#\$\^]{3,32})\"?'?",
            "password-input": r"<input\s+.*name=\"password\".*value=\"([a-zA-Z0-9\!\@\#\$\^]+?)\\?\".*/>",
            "ticket": r"ticket\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{8,300})\\?\"?'?",
            "token": r"token\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{8,300})\\?\"?'?",
            "accessId": r"accessId\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "accessKey": r"accessKey\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "secretKey": r"secretKey\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "jdbc": "jdbc\:\S{2,10}\://\S([0-9a-zA-Z%\+\=\/\-\_\?\:]{16,256})",
        }
        self.regex_body_size_limit = 262144

    def is_token(self, token):
        if token == None or token.strip().rstrip() == '':
            return False
        for black_tolen in self.black_token_list:
            if black_tolen in token.lower():
                return False
        return True

    def is_password(self, password):
        if password == None or password.strip().rstrip() == '':
            return False
        for black_password in self.black_password_list:
            if black_password in password.lower():
                return False
        return True

    def sensitive_infomation_check(self, text, url):
        block_length = 1024 * 4
        info_list = {}
        # 分块匹配，减轻正则压力, +256 主要是避免\u1233等字符被切割
        blocks = [text[i:i + block_length + 256] for i in range(0, len(text), block_length)]
        for block in blocks:
            try:
                block_str = re.sub(r'(\\u[\s\S]{4})', lambda x: x.group(1).encode("utf-8").decode("unicode-escape"), block)
            except:
                block_str = block
            for key in self.regex_map:
                if key not in info_list.keys():
                    info_list[key] = []
                try:
                    res = re.findall(self.regex_map[key], block_str, re.IGNORECASE)
                except Exception as e:
                    self.log.error(f"Error regex, url: {url}, error: {str(e)}")
                else:
                    for i in range(0, len(res)):
                        if (key == "password" and not self.is_password(res[i])):
                            continue
                        if (key == "pwd" and not self.is_password(res[i])):
                            continue
                        if (key == "token" and not self.is_token(res[i])):
                            continue
                        if (key == "ticket" and not self.is_token(res[i])):
                            continue
                        if res[i] not in info_list[key]:
                            info_list[key].append(res[i])
        return info_list

    async def prove(self, flow: HTTPFlow):
        ext = self.get_extension(flow)
        status = self.get_status(flow)
        response_media_type = self.get_response_media_type(flow)
        response_content_type = self.get_response_content_type(flow)
        response_content_length = self.get_response_content_length(flow)
        if (status < 400 or status > 499) and response_media_type not in self.black_media_type_list and response_content_type not in self.black_content_type \
            and ext not in self.black_ext_list and response_content_length < int(self.regex_body_size_limit):
            url = self.get_url(flow)
            response_text = self.get_response_text(flow)
            if response_text:
                info_list = self.sensitive_infomation_check(response_text, url)
                detail = ''
                for key in self.regex_map:
                    if key in info_list.keys() and len(info_list[key]) >= 1:
                        detail += "Found {key}: {value}; \r\n".format(key=key, value=', '.join(info_list[key]))

                if detail != '':
                    detail = detail
                    await self.save_vul(flow, detail)