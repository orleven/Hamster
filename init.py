#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import asyncio
import warnings
from argparse import ArgumentParser
from sqlalchemy.sql import text
from sqlalchemy.ext.asyncio import create_async_engine
from lib.core.g import conf
from lib.core.g import mysql
from lib.core.g import async_engine
from lib.core.g import async_session
from lib.core.model import Base
from lib.core.model import User
from lib.core.model import DictPassword
from lib.core.model import DictUsername
from lib.core.model import ScanBlack
from lib.core.model import ScanWhite
from lib.core.model import VulFilter
from lib.core.enums import ScanMatchPosition
from lib.core.enums import ScanMatchType
from lib.core.enums import UserRole
from lib.util.util import get_time
from lib.util.util import random_string

warnings.filterwarnings("ignore", module=r"aiomysql")


async def create_table(flag=False):
    """
    创建数据库、表结构
    :return:
    """
    # 创建数据库
    async_sqlalchemy_database_url_without_db = mysql.get_async_sqlalchemy_database_url_without_db()
    temp_async_engine = create_async_engine(async_sqlalchemy_database_url_without_db)
    async with temp_async_engine.begin() as session:
        await session.execute(text(f"CREATE DATABASE IF NOT EXISTS `{mysql.dbname}` CHARACTER SET {mysql.charset} COLLATE {mysql.collate};"))
        await session.commit()

    # 初始化表结构
    async with async_engine.begin() as session:
        if flag:
            await session.run_sync(Base.metadata.drop_all)
        await session.run_sync(Base.metadata.create_all)
        await session.commit()

async def init_filter_list():
    filter_list = [
        {"match_position": ScanMatchPosition.RESPONSE_BODY, "value": u'g.alicdn.com/sd/punish/waf_block', "match_type": ScanMatchType.IN},
    ]
    async with async_session.begin() as session:
        for filter in filter_list:
            match_position = filter["match_position"]
            value = filter["value"]
            match_type = filter["match_type"]
            update_time = get_time()
            filter = VulFilter(match_position=match_position, value=value, match_type=match_type,
                              update_time=update_time)
            session.add(filter)
        await session.commit()

async def init_black_list():
    black_list = [
        {"match_position": ScanMatchPosition.METHOD, "value": u"DELETE", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.METHOD, "value": u"OPSTIONS", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.PATH, "value": u"/wp-", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u".min.js", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u"/docs/", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u"/examples/jsp/", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u".css", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u".svg", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u"/gitbook/", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.PATH, "value": u"/resource/upload/", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"firefox.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"firefoxchina.cn", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"mozilla.org", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"mozilla.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"mozilla.net", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"g-fox.cn", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"gitee.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"portswigger.net", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"google.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"google-analytics.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"googletagmanager.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"googleusercontent.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"googleapis.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"trackingio.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"github.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"githubassets.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"gitlab.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"getui.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"gov.cn", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"org.cn", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"123cha.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"edu.cn", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"cnzz.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"189.cn", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"360buyimg.com", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.HOST, "value": u"39.102.194.95", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.HOST, "value": "localhost", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.HOST, "value": "127.0.0.1", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.METHOD, "value": "DELETE", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.METHOD, "value": "OPTIONS", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.METHOD, "value": "CONNECT", "match_type": ScanMatchType.EQUAL},
        {"match_position": ScanMatchPosition.HOST, "value": ".*\d{5}.cn", "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": ".*refresh.*", "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": ".*delete.*", "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": ".*clear.*", "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": '.*insert.*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": '.*save.*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": '.*remove.*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": "(/\S+)\1/", "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.PATH, "value": u"/\d{4}/\d{2}/\d{2}/", "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://10\..*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://100\..*',  "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://172\..*',  "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://192\..*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.HOST, "value": conf.platform.dnslog_top_domain, "match_type": ScanMatchType.IN},
    ]
    async with async_session.begin() as session:
        for black in black_list:
            match_position = black["match_position"]
            value = black["value"]
            match_type = black["match_type"]
            update_time = get_time()
            black = ScanBlack(match_position=match_position, value=value, match_type=match_type,  update_time=update_time)
            session.add(black)
        await session.commit()


async def init_white_list():

    white_list = [
        {"match_position": ScanMatchPosition.HOST, "value": ".", "match_type": ScanMatchType.IN},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://10\..*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://100\..*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://172\..*', "match_type": ScanMatchType.REGEX},
        {"match_position": ScanMatchPosition.URL, "value": '^(http|https)://192\..*', "match_type": ScanMatchType.REGEX},
    ]
    async with async_session.begin() as session:
        for white in white_list:
            match_position = white["match_position"]
            value = white["value"]
            match_type = white["match_type"]
            update_time = get_time()
            white = ScanWhite(match_position=match_position, value=value, match_type=match_type, update_time=update_time)
            session.add(white)
        await session.commit()


async def init_username_list():
    username_list = [
        "admin",
        "tomcat",
        "manager",
        "role",
        "security",
        "administrator",
        "super",
        "root",
        "web",
        "test",
        "test1",
        "test2",
        "test123",
        "guest",
        "user",
        "user1",
        "user2",
        "user123",
    ]
    async with async_session.begin() as session:
        for value in username_list:
            update_time = get_time()
            username_data = DictUsername(value=value,  update_time=update_time)
            session.add(username_data)
        await session.commit()

async def init_password_list():
    password_list = [
        "%user%",
        "%user%123",
        "%user%1234",
        "%user%123456",
        "%user%12345",
        "%user%888",
        "%user%@123",
        "%user%@123456",
        "%user%@12345",
        "%user%#123",
        "%user%#123456",
        "%user%#12345",
        "%user%_123",
        "%user%_123456",
        "%user%_12345",
        "%user%123!@#",
        "%user%!@#$",
        "%user%!@#",
        "%user%~!@",
        "%user%!@#123",
        "%user%2017",
        "%user%2016",
        "%user%2015",
        "%user%2018",
        "%user%2019",
        "%user%2020",
        "%user%2021",
        "%user%2022",
        "%user%@2019",
        "%user%@2020",
        "%user%@2021",
        "%user%@2022",
        "%user%@2018",
        "%user%@2017",
        "%user%@2016",
        "%user%@2015",
        "Passw0rd",
        "tomcat",
        "123456",
        "password",
        "123",
        "1",
        "123123",
        "1q2w3e4r",
        "1qaz2wsx",
        "1qaz@WSX",
        "1qazXSW@123",
        "1qaz2wsx#EDC",
        "123qwe",
        "123qaz",
        "111111",
        "Aa123456",
        "123456qwerty",
        "qwer1234",
        "12345678",
        "1q2w3e",
        "abc123",
        "123456789",
        "q1w2e3r4",
        "abcd1234",
    ]
    async with async_session.begin() as session:
        for value in password_list:
            update_time = get_time()
            password_data = DictPassword(value=value, update_time=update_time)
            session.add(password_data)
        await session.commit()


async def init_user():
    default_mail_siffix = conf.basic.default_mail_siffix
    user_list = [
        {"email": f"admin@{default_mail_siffix}", "description": u"administrator", "username": "admin",  "role": UserRole.ADMIN},
    ]
    async with async_session.begin() as session:
        for user in user_list:
            email = user["email"]
            username = user["username"]
            description = user["description"]
            role = user["role"]
            update_time = get_time()
            user = User(email=email, username=username, description=description, role=role, update_time=update_time, api_key=random_string(32))
            user.password = user.generate_password_hash(conf.basic.default_password)
            session.add(user)
        await session.commit()


async def run(args):
    """
    运行相关初始化函数
    :return:
    """
    await create_table()
    await init_user()
    await init_filter_list()
    await init_black_list()
    await init_white_list()
    await init_username_list()
    await init_password_list()

def main(args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run(args))
    except KeyboardInterrupt:
        pass


def arg_set(parser):
    parser.add_argument("-d", "--debug", action='store_true', help="Run debug", default=False)
    parser.add_argument("-h", "--help", action='store_true', help="Show help", default=False)
    return parser

if __name__ == '__main__':
    parser = ArgumentParser(add_help=False)
    parser = arg_set(parser)
    args = parser.parse_args()
    if args.help:
        parser.print_help()
    else:
        main(args)

