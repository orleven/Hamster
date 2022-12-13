from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession

class Addon(AgentAddon):
    """
    Druid未授权访问
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'DruidUnauth'
        self.addon_type = AddonType.DIR_ALL
        self.vul_name = "Druid未授权访问"
        self.level = VulLevel.MEDIUM
        self.vul_type = VulType.UNAUTHORIZED_ACCESS
        self.description = "Druid是阿里巴巴数据库出品的，为监控而生的数据库连接池，并且Druid提供的监控功能，监控SQL的执行时间、监控Web URI的请求、Session监控，首先Druid是不存在什么漏洞的。但当开发者配置不当时就可能造成未授权访问。"
        self.impact = "1. 敏感信息泄露"
        self.suggestions = "1. 对敏感文件进行权限控制或者删除处理。"
        self.scopen = ""
        self.mark = ""
        self.dir_list = [
            "",
            'druid/',
            'server/druid/',
            'api/druid/',
            'app/druid/',
            'api/app/druid/',
        ]
        self.file_list = [
            'console.html',
            'sql.html',
            'index.html',
        ]

    async def prove(self, flow: HTTPFlow):
        url_no_query = self.get_url_no_query(flow)
        method = self.get_method(flow)
        if method in ['GET']:
            if url_no_query[-1] == '/':
                async with ClientSession(self.addon_path) as session:
                    headers = self.get_request_headers(flow)
                    for dir_path in self.dir_list:
                        for file_path in self.file_list:
                            url = url_no_query + dir_path + file_path
                            async with session.get(url=url, headers=headers, allow_redirects=False) as res:
                                if res and res.status == 200:
                                    text_source = await res.text()
                                    text = text_source.lower()
                                    if 'druid stat index' in text or "druid version" in text or 'druid indexer' in text or 'druid sql stat' in text or 'druid monitor' in text:
                                        detail = text_source
                                        await self.save_vul(res, detail)
