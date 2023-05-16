#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession
from lib.util.xrayutil import *

class Addon(AgentAddon):
    """
    XrayAdapter
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'XrayAdapter'
        self.addon_type = AddonType.HOST_ONCE
        self.vul_name = "XrayPOC调用"
        self.level = VulLevel.MEDIUM
        self.vul_type = VulType.NONE
        self.scopen = ""
        self.description = "XrayPOC调用。"
        self.impact = "1. 具体请看Xray POC。"
        self.suggestions = "1. 具体请看Xray POC。"
        self.scopen = "1. 具体请看Xray POC。"
        self.mark = "1. 具体请看Xray POC。"

        self.dnslog_domain = '{value}.xray.' + self.dnslog_top_domain

        self.yaml_file_dir = 'poc/xray/pocs/'

        self.xray_poc_list = import_xray_poc_file(self.yaml_file_dir, self.dnslog_domain)


    async def prove(self, flow: HTTPFlow):

        async with ClientSession(self.addon_path) as session:
            for xray_poc in self.xray_poc_list:
                try:
                    self.log.debug(f"Start scan xray poc: {xray_poc.name}")
                    flag = True

                    # 依次加载请求rule
                    for name, rule in xray_poc.rules.items():

                        # 变量初始化
                        method = self.get_method(flow)
                        base_url = self.get_base_url(flow)
                        headers = self.get_request_headers(flow)
                        data = self.get_request_content(flow)
                        follow_redirects = False
                        path = self.get_path_no_query(flow)

                        rule_request = rule.get("request", {})
                        expression = rule.get("expression", {})
                        output = rule.get("output", {})
                        search = output.get("search", None)

                        # 请求初始化
                        method, path, headers, data, follow_redirects = xray_poc.generate_request_by_rule_request(rule_request, method, path, headers, data, follow_redirects)
                        url = base_url[:-1] + path

                        # 是否dnslog需要
                        if xray_poc.dnslog_wait:
                            keyword = xray_poc.dnslog_domain
                        else:
                            keyword = None

                        # 请求
                        async with session.request(method, url, data=data, headers=headers, allow_redirects=follow_redirects, keyword=keyword) as res:

                            if res:
                                res_status = res.status
                                res_headers = res.headers
                                res_content = await res.read()

                                # 处理cel表达式
                                xray_poc.rules_result[name] = xray_poc.deal_cel(expression, res_status, res_headers,
                                                                                res_content)
                                if search:

                                    # 如果有serach情况，需要执行search cel表达式
                                    search = xray_poc.deal_cel(search, res_status, res_headers, res_content)
                                    if search:
                                        xray_poc.search = search
                            else:
                                flag = False
                                break

                            # 校验总的cel表达式
                            if flag and xray_poc.deal_cel(xray_poc.expression):
                                detail = xray_poc.name + "\r\n" + xray_poc.detail
                                await self.save_vul(res, detail)

                    self.log.debug(f"Final scan xray poc: {xray_poc.name}")
                except TimeoutError:
                    self.log.error(f"Error scan xray poc: {xray_poc.name}, error: {str(e)}")
                except Exception as e:
                    self.log.error(f"Error scan xray poc: {xray_poc.name}, error: {str(e)}")
                    traceback.print_exc()