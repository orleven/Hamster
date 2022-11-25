#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import BLOB
from sqlalchemy import Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from lib.core.g import async_engine
from lib.core.g import conf
from lib.core.enums import UserStatus
from lib.core.enums import EngineStatus
from lib.util.util import get_time
from lib.util.util import get_time_str
from lib.util.util import random_string
from lib.util.util import get_timedelta
from lib.util.cipherutil import jwtdecode
from lib.util.cipherutil import jwtencode

Base = declarative_base(async_engine)


class Cache(Base):
    """Cache"""
    __tablename__ = "cache"  # 指明数据库表名
    id = Column(Integer(), primary_key=True, autoincrement=True)  # 主键 整型的主键默认设置为自增
    keyword = Column(String(155), unique=True)
    scheme = Column(String(10))
    method = Column(String(10))
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    request_http_version = Column(String(20))
    request_headers = Column(Text())
    request_content_length = Column(Integer())
    request_content = Column(BLOB(131070))
    response_reason = Column(String(255))
    response_http_version = Column(String(20))
    response_status_code = Column(Integer())
    response_headers = Column(Text())
    response_content_length = Column(Integer())
    response_content_type = Column(Text())
    response_content = Column(BLOB(131070))
    websocket_type = Column(String(255))
    websocket_content = Column(BLOB(131070))
    # addon_id = Column(Integer, ForeignKey("addon.id"))
    addon_path = Column(String(255))
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "keyword": self.keyword,
            "request_http_version": self.request_http_version,
            # "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            # "request_content": self.request_content,
            # "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            # "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            "websocket_content": self.websocket_content,
            "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "addon_path": self.addon_path,
        }
        return json_data

    def all_to_json(self):
        json_data = {
            "id": self.id,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "keyword": self.keyword,
            "request_http_version": self.request_http_version,
            "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            "request_content": self.request_content,
            "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            "websocket_content": self.websocket_content,
            "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "addon_path": self.addon_path,
        }
        return json_data


class Packet(Base):
    __tablename__ = "packet"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    scheme = Column(String(10))
    method = Column(String(10))
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    request_http_version = Column(String(20))
    request_headers = Column(Text())
    request_content_length = Column(Integer())
    request_content = Column(BLOB(131070))
    response_reason = Column(String(255))
    response_http_version = Column(String(20))
    response_status_code = Column(Integer())
    response_headers = Column(Text())
    response_content_length = Column(Integer())
    response_content_type = Column(Text())
    response_content = Column(BLOB(131070))
    websocket_type = Column(String(255))
    websocket_content = Column(BLOB(131070))
    client_conn_sni = Column(String(255))
    server_conn_sni = Column(String(255))
    client_conn_cipher_name = Column(String(255))
    server_conn_cipher_name = Column(String(255))
    client_conn_tls_version = Column(String(255))
    server_conn_tls_version = Column(String(255))
    client_conn_address = Column(String(255))
    server_conn_address = Column(String(255))  # packet.server_conn.address # dns解析前
    client_conn_ip_address = Column(String(255))
    server_conn_ip_address = Column(String(255))  # packet.server_conn.peername # dns解析后
    client_conn_proxy_address = Column(String(255))
    server_conn_proxy_address = Column(String(255))  # packet.server_conn.sockname #代理中转
    # request_date_start = Column(String(20))
    # request_date_end = Column(String(20))
    # response_date_start = Column(String(20))
    # response_date_end = Column(String(20))
    # client_conn_tls_established = Column(Boolean())
    # client_conn_alpn_proto_negotiated = Column(String(255))
    # client_conn_data_start = Column(String(20))
    # client_conn_data_tls = Column(String(20))
    # client_conn_data_end = Column(String(20))
    # server_conn_tls_established = Column(Boolean())
    # server_conn_alpn_proto_negotiated = Column(String(255))
    # server_conn_data_start = Column(String(20))
    # server_conn_data_tcp = Column(String(20))
    # server_conn_data_tls = Column(String(20))
    # server_conn_data_end = Column(String(20))
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "request_http_version": self.request_http_version,
            # "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            # "request_content": self.request_content,
            # "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            # "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            # "websocket_content": self.websocket_content,
            # "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class Addon(Base):
    """扫描插件"""
    __tablename__ = "addon"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    addon_md5 = Column(String(32))
    addon_path = Column(String(155), unique=True)
    addon_name = Column(String(255))
    addon_type = Column(String(255))
    addon_file_name = Column(String(255))
    vul_name = Column(String(255))
    level = Column(String(255))
    vul_type = Column(String(255))
    description = Column(Text())
    scopen = Column(Text())
    impact = Column(Text())
    suggestions = Column(Text())
    file_update_time = Column(DateTime())
    file_create_time = Column(DateTime())
    update_time = Column(DateTime(), default=get_time())
    enable = Column(Boolean(), default=True)
    mark = Column(Text())

    vul_list = relationship("Vul", backref="addon")

    # cache_list = relationship("Cache", backref="addon")

    def to_json(self):
        json_data = {
            "id": self.id,
            "addon_md5": self.addon_md5,
            "addon_type": self.addon_type,
            "addon_file_name": self.addon_file_name,
            "addon_path": self.addon_path,
            "vul_name": self.vul_name,
            "addon_name": self.addon_name,
            "level": self.level,
            "description": self.description,
            "suggestions": self.suggestions,
            "impact": self.impact,
            "scopen": self.scopen,
            "file_update_time": get_time_str(self.file_update_time) if self.file_update_time else None,
            "file_create_time": get_time_str(self.file_create_time) if self.file_create_time else None,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "vul_type": self.vul_type,
            "mark": self.mark,
            "enable": self.enable
        }
        return json_data


class Vul(Base):
    """漏洞"""
    __tablename__ = "vul"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    scheme = Column(String(10))
    method = Column(String(10))
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    request_http_version = Column(String(20))
    request_headers = Column(Text())
    request_content_length = Column(Integer())
    request_content = Column(BLOB(131070))
    response_reason = Column(String(255))
    response_http_version = Column(String(20))
    response_status_code = Column(Integer())
    response_headers = Column(Text())
    response_content_length = Column(Integer())
    response_content_type = Column(Text())
    response_content = Column(BLOB(131070))
    websocket_type = Column(String(255))
    websocket_content = Column(BLOB(131070))
    detail = Column(Text())
    mark = Column(Text())
    update_time = Column(DateTime(), default=get_time())
    addon_id = Column(Integer, ForeignKey("addon.id"))
    addon_path = Column(String(255))
    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "request_http_version": self.request_http_version,
            # "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            # "request_content": self.request_content,
            # "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            # "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            "detail": self.detail,
            "vul_type": self.addon.vul_type if self.addon is not None else "",
            "vul_name": self.addon.vul_name if self.addon is not None else "",
            "addon_name": self.addon.addon_name if self.addon is not None else "",
            "level": self.addon.level if self.addon is not None else "",
            "description": self.addon.description if self.addon is not None else "",
            "suggestions": self.addon.suggestions if self.addon is not None else "",
            "impact": self.addon.impact if self.addon is not None else "",
            "scopen": self.addon.scopen if self.addon is not None else "",
            # "websocket_content": self.websocket_content,
            # "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "addon_path": self.addon_path,
            "mark": self.mark,
        }
        return json_data

    def all_to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "request_http_version": self.request_http_version,
            "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            "request_content": self.request_content,
            "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            "detail": self.detail,
            "vul_type": self.addon.vul_type if self.addon is not None else "",
            "vul_name": self.addon.vul_name if self.addon is not None else "",
            "addon_name": self.addon.addon_name if self.addon is not None else "",
            "level": self.addon.level if self.addon is not None else "",
            "description": self.addon.description if self.addon is not None else "",
            "suggestions": self.addon.suggestions if self.addon is not None else "",
            "impact": self.addon.impact if self.addon is not None else "",
            "scopen": self.addon.scopen if self.addon is not None else "",
            "websocket_content": self.websocket_content,
            "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "mark": self.mark,
        }
        return json_data

class CollectJsonp(Base):
    """Jsonp"""
    __tablename__ = "collect_jsonp"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    scheme = Column(String(10))
    method = Column(String(10))
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    request_http_version = Column(String(20))
    request_headers = Column(Text())
    request_content_length = Column(Integer())
    request_content = Column(BLOB(131070))
    response_reason = Column(String(255))
    response_http_version = Column(String(20))
    response_status_code = Column(Integer())
    response_headers = Column(Text())
    response_content_length = Column(Integer())
    response_content_type = Column(Text())
    response_content = Column(BLOB(131070))
    websocket_type = Column(String(255))
    websocket_content = Column(BLOB(131070))
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "request_http_version": self.request_http_version,
            # "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            # "request_content": self.request_content,
            # "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            # "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            # "websocket_content": self.websocket_content,
            # "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class CollectCORS(Base):
    """CORS"""
    __tablename__ = "collect_cors"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    scheme = Column(String(10))
    method = Column(String(10))
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    request_http_version = Column(String(20))
    request_headers = Column(Text())
    request_content_length = Column(Integer())
    request_content = Column(BLOB(131070))
    response_reason = Column(String(255))
    response_http_version = Column(String(20))
    response_status_code = Column(Integer())
    response_headers = Column(Text())
    response_content_length = Column(Integer())
    response_content_type = Column(Text())
    response_content = Column(BLOB(131070))
    websocket_type = Column(String(255))
    websocket_content = Column(BLOB(131070))
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "scheme": self.scheme,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "request_http_version": self.request_http_version,
            # "request_headers": self.request_headers,
            "request_content_length": self.request_content_length,
            # "request_content": self.request_content,
            # "response_content": self.response_content,
            "response_http_version": self.response_http_version,
            "response_status_code": self.response_status_code,
            "response_reason": self.response_reason,
            # "response_headers": self.response_headers,
            "response_content_length": self.response_content_length,
            "response_content_type": self.response_content_type,
            # "websocket_content": self.websocket_content,
            # "websocket_type": self.websocket_type,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class CollectFingerPrint(Base):
    """指纹"""
    __tablename__ = "collect_finger_print"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    result = Column(String(255))
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "result": self.result,
            "update_time": get_time_str(self.update_time),
        }
        return json_data


class CollectParam(Base):
    """参数"""
    __tablename__ = "collect_param"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    path = Column(Text())
    param = Column(String(255))
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "path": self.path,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "param": self.param,
        }
        return json_data


class CollectPath(Base):
    """路径"""
    __tablename__ = "collect_path"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    path = Column(Text())
    dir = Column(Text())
    file = Column(Text())
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "path": self.path,
            "dir": self.dir,
            "file": self.file,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class CollectEmail(Base):
    """邮箱地址"""
    __tablename__ = "collect_email"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    host = Column(String(255))
    port = Column(Integer())
    url = Column(Text())
    email = Column(Text())
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "md5": self.md5,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "email": self.email,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class ScanWhite(Base):
    """扫描白名单"""
    __tablename__ = "scan_white"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    match_position = Column(String(255))
    value = Column(String(255))
    match_type = Column(String(255))
    update_time = Column(DateTime(), default=get_time())
    mark = Column(Text())

    def to_json(self):
        json_data = {
            "id": self.id,
            "match_position": self.match_position,
            "value": self.value,
            "match_type": self.match_type,
            "mark": self.mark,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class ScanBlack(Base):
    """扫描黑名单"""
    __tablename__ = "scan_black"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    match_position = Column(String(255))
    value = Column(String(255))
    match_type = Column(String(255))
    update_time = Column(DateTime(), default=get_time())
    mark = Column(Text())

    def to_json(self):
        json_data = {
            "id": self.id,
            "match_position": self.match_position,
            "value": self.value,
            "match_type": self.match_type,
            "mark": self.mark,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data

class ScanTime(Base):
    """扫描时间"""

    __tablename__ = "scan_time"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    match_position = Column(String(255))
    value = Column(String(255))
    match_type = Column(String(255))
    start_time = Column(String(255))
    end_time = Column(String(255))
    update_time = Column(DateTime(), default=get_time())
    mark = Column(Text())

    def to_json(self):
        json_data = {
            "id": self.id,
            "match_position": self.match_position,
            "value": self.value,
            "match_type": self.match_type,
            "mark": self.mark,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }
        return json_data

class DictUsername(Base):
    """用户名字典"""
    __tablename__ = "dict_username"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    value = Column(String(255))
    update_time = Column(DateTime(), default=get_time())
    mark = Column(Text())

    def to_json(self):
        json_data = {
            "id": self.id,
            "value": self.value,
            "mark": self.mark,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class DictPassword(Base):
    """密码字典"""
    __tablename__ = "dict_password"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    value = Column(String(255))
    update_time = Column(DateTime(), default=get_time())
    mark = Column(Text())

    def to_json(self):
        json_data = {
            "id": self.id,
            "value": self.value,
            "mark": self.mark,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class Engine(Base):
    """引擎"""
    __tablename__ = "engine"
    id = Column(String(155), primary_key=True)
    name = Column(String(255))
    ip = Column(String(40))
    engine_type = Column(String(255))
    description = Column(Text())
    status = Column(String(255), default=EngineStatus.OK)
    mark = Column(Text())
    create_time = Column(DateTime(), default=get_time())
    update_time = Column(DateTime(), default=get_time())
    task_num = Column(Integer(), default=0)
    scan_max_task_num = Column(Integer(), default=conf.scan.scan_max_task_num)
    queue_num = Column(Integer(), default=0)

    def to_json(self):
        json_data = {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "description": self.description,
            "status": self.status,
            "engine_type": self.engine_type,
            "mark": self.mark,
            "create_time": get_time_str(self.create_time) if self.create_time else None,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "task_num": self.task_num,
            "scan_max_task_num": self.scan_max_task_num,
            "queue_num": self.queue_num,
        }
        return json_data


class DNSLog(Base):
    """DNSLog"""
    __tablename__ = "dnslog"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    ip = Column(String(255))
    keyword = Column(String(255))
    create_time = Column(DateTime(), default=get_time())
    update_time = Column(DateTime(), default=get_time())

    def to_json(self):
        json_data = {
            "id": self.id,
            "ip": self.ip,
            "keyword": self.keyword,
            "create_time": get_time_str(self.create_time) if self.create_time else None,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
        }
        return json_data


class Log(Base):
    """Log"""
    __tablename__ = "log"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    ip = Column(String(40))
    log_type = Column(String(255))
    description = Column(Text())
    url = Column(Text())
    update_time = Column(DateTime(), default=get_time())

    user_id = Column(Integer, ForeignKey("user.id"))
    user = relationship("User")

    def to_json(self):
        json_data = {
            "id": self.id,
            "ip": self.ip,
            "log_type": self.log_type,
            "description": self.description,
            "url": self.url,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "user": self.user.username if self.user else self.user,
            "user_id": self.user_id,
        }
        return json_data


class User(Base):
    """User"""
    __tablename__ = "user"
    id = Column(Integer(), primary_key=True, autoincrement=True)
    email = Column(String(155), unique=True)
    username = Column(String(255))
    description = Column(Text())
    password = Column(String(255))
    status = Column(String(255), default=UserStatus.OK)
    role = Column(String(255))
    api_key = Column(String(255), default=random_string(32))
    login_failed = Column(Integer(), default=0)
    fail_time = Column(DateTime())
    create_time = Column(DateTime(), default=get_time())
    login_time = Column(DateTime())
    update_time = Column(DateTime(), default=get_time())
    mark = Column(Text())

    def to_json(self):
        json_data = {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "description": self.description,
            "status": self.status,
            "login_failed": self.login_failed,
            "fail_time": get_time_str(self.fail_time) if self.fail_time else None,
            "create_time": get_time_str(self.create_time) if self.create_time else None,
            "login_time": get_time_str(self.login_time) if self.login_time else None,
            "update_time": get_time_str(self.update_time) if self.update_time else None,
            "mark": self.mark,
        }
        return json_data

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def generate_password_hash(self, password=None):
        if password is None:
            password = self.password
        return generate_password_hash(password)

    def generate_auth_token(self, expiration=3600):
        message = {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "status": self.status,
            "role": self.role,
            "exp": get_time() + get_timedelta(seconds=expiration)
        }
        token = jwtencode(message, conf.basic.secret_key, algorithm="HS256")
        return token

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwtdecode(token, conf.basic.secret_key, algorithms=["HS256"], do_time_check=True)
            if data and isinstance(data, dict):
                from lib.hander import db
                return db.session.query(User).get(data["id"])
        except:
            return None

        return None
