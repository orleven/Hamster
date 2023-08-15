#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import os
import sys
import socket
from datetime import timedelta
from lib.util.configutil import parser_conf

# 不生成pyc
sys.dont_write_bytecode = True

# 最低python运行版本
REQUIRE_PY_VERSION = (3, 9)

# 检测当前运行版本
RUN_PY_VERSION = sys.version_info
if RUN_PY_VERSION < REQUIRE_PY_VERSION:
    exit(f"[-] Incompatible Python version detected ('{RUN_PY_VERSION}). For successfully running program you'll have to use version {REQUIRE_PY_VERSION}  (visit 'http://www.python.org/download/')")

# 项目名称
PROJECT_NAME = "Hamster"

# 当前扫描器版本
VERSION = "1.0"

# 版本描述
# VERSION_STRING = f"{PROJECT_NAME}/{VERSION}"
VERSION_STRING = "X"

# 当前运行入口文件
MAIN_NAME = os.path.split(os.path.splitext(sys.argv[0])[0])[-1]

# 当前运行路径
ROOT_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 日志路径
LOG = 'log'
LOG_PATH = os.path.join(ROOT_PATH, LOG)

# 配置路径
CONFIG = 'conf'
ENV_CONFIG_PATH = os.path.join(ROOT_PATH, CONFIG)

# 运行环境
ENV_CONFIG_FILE_PATH = os.path.join(ENV_CONFIG_PATH, f"{PROJECT_NAME.lower()}_env.conf")
config_file_list = [(ENV_CONFIG_FILE_PATH, {("env", f"This is a env config for {PROJECT_NAME}"): {("env", "Run env"): "online"}})]
env_conf = parser_conf(config_file_list)
ENV = env_conf.env.env.lower()

# 配置文件路径
CONFIG_PATH = os.path.join(ENV_CONFIG_PATH, ENV)
BASIC_CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, f"{PROJECT_NAME.lower()}_basic.conf")
SIMPLE_CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, f"{PROJECT_NAME.lower()}_simple.conf")
SERVER_CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, f"{PROJECT_NAME.lower()}_server.conf")
AGENT_CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, f"{PROJECT_NAME.lower()}_agent.conf")
SUPPORT_CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, f"{PROJECT_NAME.lower()}_support.conf")
MANAGER_CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, f"{PROJECT_NAME.lower()}_manager.conf")

# 模版文件路径
TEMPLATE = 'template'
TEMPLATE_PATH = os.path.join(ROOT_PATH, TEMPLATE)

# 静态文件路径
STATIC = 'static'
STATIC_PATH = os.path.join(ROOT_PATH, STATIC)

# 相关Addon路径
ADDON = 'addon'
ADDON_PATH = os.path.join(ROOT_PATH, ADDON)

# Agent addon路径
AGENT_ADDON = 'agent'
AGENT_ADDON_PATH = os.path.join(ADDON_PATH, AGENT_ADDON)

# Agent addon路径
TEST_ADDON = 'test'
TEST_ADDON_PATH = os.path.join(ADDON_PATH, TEST_ADDON)

# Server addon路径
SERVER_ADDON = 'server'
SERVER_ADDON_PATH = os.path.join(ADDON_PATH, SERVER_ADDON)

# Support addon路径
SUPPORT_ADDON = 'support'
SUPPORT_ADDON_PATH = os.path.join(ADDON_PATH, SUPPORT_ADDON)

# Common addon路径
COMMON_ADDON = 'common'
COMMON_ADDON_PATH = os.path.join(ADDON_PATH, COMMON_ADDON)

# 当前运行主机名称
HOSTNAME = socket.gethostname()

# WEB 调试模式
WEB_DEBUG = False

# 静态文件缓存
SEND_FILE_MAX_AGE_DEFAULT = timedelta(hours=1)

# Web 路径前缀
PREFIX_URL = "/" + PROJECT_NAME.lower() + "/" + ENV

REDIS_SCAN_RECODE_PRIFIX = 'ScanRecode'
REDIS_SCAN_QPS_LIMIT_PREFIX = 'QPSLimit'

HALT = 'odjaodoka193891u12'
