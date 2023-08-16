#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from asyncio import Queue
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from lib.core.log import Logger
from lib.core.config import config_parser
from lib.core.mysql import Mysql
from lib.core.rabbitmq import RabbitMQ
from lib.core.redis import Redis

# 配置存储
conf = config_parser()

# task扫码队列
task_queue = Queue()

# rabbitmq保存队列
mq_queue = Queue()

# 漏洞数据保存队列
vul_queue = Queue()

# 缓存数据数据保存队列
cache_queue = Queue()

# 非漏洞其他model数据保存队列
packet_queue = Queue()
email_queue = Queue()
path_queue = Queue()
param_queue = Queue()
jsonp_queue = Queue()
cors_queue = Queue()

# 缓存日志
cache_log = Logger(name='cache', use_console=False, backupCount=conf.cache.cache_log_stored_day)

# agent日志
agent_log = Logger(name='agent', use_console=True, backupCount=conf.cache.log_stored_day)

# server日志
server_log = Logger(name='server', use_console=True, backupCount=conf.cache.log_stored_day)

# support日志
support_log = Logger(name='support', use_console=True, backupCount=conf.cache.log_stored_day)

# manager日志
manager_log = Logger(name='manager', use_console=False, backupCount=conf.cache.log_stored_day)

# manager日志
simple_log = Logger(name='simple', use_console=True, backupCount=conf.cache.log_stored_day)

if 'agent' in MAIN_NAME:
    log = agent_log
elif 'support' in MAIN_NAME:
    log = support_log
elif 'manager' in MAIN_NAME:
    log = manager_log
elif 'simple' in MAIN_NAME:
    log = simple_log
else:
    log = server_log

rabbitmq = RabbitMQ(
    host=conf.rabbitmq.host,
    port=conf.rabbitmq.port,
    username=conf.rabbitmq.username,
    password=conf.rabbitmq.password,
    name=conf.rabbitmq.name
)

redis = Redis(
    host=conf.redis.host,
    port=conf.redis.port,
    username=conf.redis.username,
    password=conf.redis.password,
    decode_responses=conf.redis.decode_responses,
)

mysql = Mysql(
    host=conf.mysql.host,
    port=conf.mysql.port,
    username=conf.mysql.username,
    password=conf.mysql.password,
    dbname=conf.mysql.dbname,
    charset=conf.mysql.charset,
    collate=conf.mysql.collate,
)

async_sqlalchemy_database_url = mysql.get_async_sqlalchemy_database_url()
async_engine = create_async_engine(async_sqlalchemy_database_url)
async_session = sessionmaker(async_engine, class_=AsyncSession)

from lib.util.interactshutil import Interactsh
interactsh_client = Interactsh()