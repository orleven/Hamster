from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession

class Addon(AgentAddon):
    """
    Tomcat 敏感文件泄露扫描
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'TomcatFile'
        self.addon_type = AddonType.DIR_ALL
        self.vul_name = "Tomcat默认War包"
        self.level = VulLevel.LOWER
        self.vul_type = VulType.INFO_FILE
        self.description = "Tomcat 中间件默认安装后会存在相关war包，这些war包可能会泄露相关信息。"
        self.scopen = ""
        self.impact = "1. 泄露了Tomcat相关信息。 2. 攻击者可以对相关路径进行暴力破解，甚至获取服务器权限。"
        self.suggestions = "1. 删除默认War包或做好访问控制。"
        self.mark = ""
        self.file_list = [
            "host-manager/",
            "manager/html",
            "examples/",
            "docs/",
            "",
        ]

    async def prove(self, flow: HTTPFlow):
        url_no_query = self.get_url_no_query(flow)
        method = self.get_method(flow)
        if method in ['GET']:
            if url_no_query[-1] == '/':
                async with ClientSession(self.addon_path) as session:
                    headers = self.get_request_headers(flow)
                    for file_path in self.file_list:
                        url = url_no_query + file_path
                        async with session.get(url=url, headers=headers, allow_redirects=False) as res:
                            if res and res.status == 200:
                                text = await res.text()
                                flag = False
                                if res.status == 200 and 'Apache Tomcat Examples' in text:
                                    flag = True
                                elif res.status == 401 and '401 Unauthorized' in text and 'tomcat' in text:
                                    flag = True
                                elif res.status == 403 and '403 Access Denied' in text and 'tomcat-users' in text:
                                    flag = True
                                elif res.status == 200 and 'Documentation' in text and 'Apache Software Foundation' in text and 'tomcat' in text:
                                    flag = True
                                if flag:
                                    detail = text
                                    await self.save_vul(res, detail)
