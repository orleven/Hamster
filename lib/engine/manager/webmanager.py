#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from werkzeug.middleware.proxy_fix import ProxyFix
from lib.core.enums import EngineType
from lib.hander import app
from lib.core.g import conf
from lib.engine.manager import BaseManager

class WebManager(BaseManager):
    """
    Manager 控制台
    """

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.WEB_MANAGER
        self.id = f'{HOSTNAME}_{self.engine_type}'

        # 加载配置
        self.listen_host = conf.manager.listen_host
        self.listen_port = conf.manager.listen_port

    def run(self):
        app.wsgi_app = ProxyFix(app.wsgi_app)
        app.run(host=self.listen_host, port=self.listen_port)

