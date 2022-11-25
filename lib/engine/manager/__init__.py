#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from lib.engine import BaseEngine
from lib.core.g import log
from lib.core.g import conf
from lib.core.enums import EngineType
from lib.core.enums import EngineStatus
from lib.util.util import get_host_ip


class BaseManager(BaseEngine):
    """Manager 基础类"""

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.BASE_MANAGER
        self.id = f'{HOSTNAME}_{self.engine_type}'
        self.ip = get_host_ip()
        self.status = EngineStatus.OK

        # 属性初始化
        self.remaining = 0
        self.scanning = 0
        self.queue_num = 0
        self.scan_max_task_num = conf.scan.scan_max_task_num
        self.max_data_queue_num = conf.basic.max_data_queue_num


    def print_status(self):
        """打印状态"""

        log.info(f"Engine: {self.id}, Status: {self.status}")