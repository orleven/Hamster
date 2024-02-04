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
        self.name = 'SensiticeInformationWS'
        self.addon_type = AddonType.WEBSOCKET_ONCE
        self.vul_name = "敏感信息泄露"
        self.level = VulLevel.LOWER
        self.vul_type = VulType.INFO
        self.description = "敏感信息泄露，由于错误处理系统数据信息或系统存在安全漏洞，导致敏感信息的泄露。"
        self.scopen = ""
        self.impact = "1. 敏感信息泄露。 2. 攻击者可以收集泄露的敏感信息并进行整合用以结合其他安全风险及漏洞进行进一步的攻击。"
        self.suggestions = "1. 对敏感信息进行脱敏处理。"
        self.mark = ""

        self.black_mail_domian_list = [
            '.css', '.gif', '.jpg', '.png', '.ico', '.js', '.jpeg', '.gif', '.woff', '.ttf', 'github.com', "dcode.io",
            "github.com", "feross.org"
        ]
        self.black_url_list = [
            '.css', '.gif', '.jpg', '.png', '.ico', '.js', '.jpeg', '.gif', '.woff', '.ttf', 'github.com', "dcode.io",
            "github", "feross.org", ".svg", ".font", "sso", "login", "regi", "sign", "auth", "captcha", "npms.io",
            "reactjs", "/o?",  "/t?",
            "/2?", "/n/o?", "/a?", "chromium", "bugs", "mozilla",
        ]
        self.black_password_list = [
            "sso", "function", "this", "that", "define", "storage", "instruction", "__", "true", "false", "text",
            "hidden", "null", "before", "code", "input", "async", "change", "pend", "hide", "after", "new", "object",
            "string", "hover", "reset", "return", "void", "escape", "crypt", "8192", "digit", "alidate", "web", "call",
            "webpack", "ield", "onfirm", "ucce", "navi", "alid", "deep", "olumn", "eve", "ase", "ist",
            "has", "attr", "rigin", "hart", "utton", "allow", "comm", "how", "anel", "ist", "lect", "etch",  "ime",
            "ame", "proxy", "oken", "onfig", "get", "able", "uto", "ini", "ttrs", "dis", "add", "set",
            "tion", "ate", "key", "remove", "del", "hand", "load", "upd", "rend", "age", "ent", "md5", "index", "wind",
            "rror", "track", "form", "ize", "croll", "eight", "nvoke", "stop", "start", "english"
        ]
        self.black_token_list = self.black_password_list
        self.black_key_list = self.black_password_list
        self.regex_map = {
            # "mail": r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+)",
            # "host": r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:[0-9]{0,5}]{0,1})",
            # "ip": r"((?:(?:2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(?:2[0-4]\d|25[0-5]|[01]?\d\d?))",
            "ak": r"ak\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "sk": r"sk\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "url": r"((?:\/[0-9a-zA-Z\_\-\.]{1,32})+\?[0-9a-zA-Z\_\-]{1,32}=[0-9a-zA-Z%\+\=\/\-\_\.]{0,300}(?:\&[0-9a-zA-Z\_\-]{1,32}=*(?:[0-9a-zA-Z%\+\=\/\-\_\.]{0,300})+)*)",
            "password": r"password\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([a-zA-Z0-9\!\@\#\$\^]{3,32})\\?\"?'?",
            "pwd": r"pwd\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([a-zA-Z0-9\!\@\#\$\^]{3,32})\"?'?",
            "key": r"key\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{8,300})\\?\"?'?",
            "ticket": r"ticket\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{8,300})\\?\"?'?",
            "token": r"token\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{8,300})\\?\"?'?",
            "accessId": r"accessId\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "accessKey": r"accessKey\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "secretKey": r"secretKey\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "apiID": r"apiID\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "apiKey": r"apiKey\\?'?\"?[\t\n\r ]*[\:\=][\t\n\r ]*\\?\"?'?([0-9a-zA-Z%\+\=\/\-\_]{16,64})\\?\"?'?",
            "jdbc": r"jdbc\:\S{2,10}\://\S[0-9a-zA-Z%\+\=\/\-\_\?\:]{16,256}",
            "auth": r"[a-z]{2,8}\://[a-zA-Z0-9_.+-]+\:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+",
            "password-input": r"<input\s+.*name=\"password\".*value=\"([a-zA-Z0-9\!\@\#\$\^]+?)\\?\".*/>",
        }
        self.regex_body_size_limit = 8388480

    def is_token(self, token):
        if token == None or token.strip().rstrip() == '':
            return False
        for black_tolen in self.black_token_list:
            if black_tolen in token.lower():
                return False
        return True

    def is_url(self, url):
        for black_url in self.black_url_list:
            if black_url in url.lower():
                return False
        return True

    def is_key(self, key):
        for black_key in self.black_key_list:
            if black_key in key.lower():
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
                        if (key == "url" and not self.is_url(res[i])):
                            continue
                        if (key == "key" and not self.is_key(res[i])):
                            continue
                        if res[i] not in info_list[key]:
                            info_list[key].append(res[i])
        return info_list

    async def prove(self, flow: HTTPFlow):
        url = self.get_url(flow)
        message = self.get_websocket_message_by_index(flow, -1)

        # 扫描message
        if message:
            response_text = message.text

            info_list = self.sensitive_infomation_check(response_text, url)
            detail = ''
            for key in self.regex_map:
                if key in info_list.keys() and len(info_list[key]) >= 1:
                    detail += "Found {key}: \r\n{value}; \r\n\r\n".format(key=key, value='\r\n'.join(info_list[key]))

            if detail != '':
                detail = detail
                await self.save_vul(flow, detail, truncation=False)