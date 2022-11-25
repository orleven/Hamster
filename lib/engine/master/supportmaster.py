#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from lib.engine.master import BaseMaster
from lib.core.g import conf
from lib.core.enums import EngineType

class SupportMaster(BaseMaster):
    """
    Support Master为辅助监听模块
    """

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.SUPPORT_MASTER
        self.id = f'{HOSTNAME}_{self.engine_type}'

        # 属性初始化
        self.addon_list = []
        self.addon_top_path_list = [SUPPORT_ADDON_PATH, COMMON_ADDON_PATH]

        # 加载配置
        self.options.listen_host = conf.support.listen_host
        self.options.listen_port = conf.support.listen_port