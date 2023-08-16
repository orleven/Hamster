#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from lib.core.enums import ScanMode
from lib.util.util import random_string
from lib.util.configutil import parser_conf

def env_config():
    configs = {
        ("env", f"This is a env config for {PROJECT_NAME}"): {
            ("env", "Run env"): "online"
        }
    }
    return configs

def basic_config():
    configs = {
        ("basic", f"This is a basic config for {PROJECT_NAME}"): {
            ("proxy_mode", "Proxy mode, http/socks5/upstream:http://127.0.0.1:8080/"): "http",
            ("proxy_auth", "HTTP Basic authentication to upstream proxy and reverse proxy requests. Format: username:password."): f"{PROJECT_NAME}:{PROJECT_NAME}@123",
            ("listen_domain", ""): f"admin.{PROJECT_NAME.lower()}.com",
            ("timeout", "Connection timeout"): 5,
            ("heartbeat_time", ""): 60,
            ("user_agent", ""): f'{VERSION_STRING} Default',
            ("max_data_queue_num", ""): 300,
            ("secret_key", "Secret key"): random_string(64),
            ("anticache", "When the anticache option is set, it removes headers (if-none-match and if-modified-since) that might elicit a 304 Not Modified response from the server. This is useful when you want to make sure you capture an HTTP exchange in its totality. It’s also often used during client-side replay, when you want to make sure the server responds with complete data."): False,
            ("default_mail_siffix", ""): f"{PROJECT_NAME.lower()}.com",
            ("default_password", ""): f"{PROJECT_NAME}@123",
        },
        ("mysql", f"This is a mysql config for {PROJECT_NAME}"): {
            ("host", ""): "127.0.0.1",
            ("port", ""): 3306,
            ("username", ""): "root",
            ("password", ""): "123456",
            ("dbname", ""): PROJECT_NAME,
            ("charset", ""): "utf8mb4",
            ("collate", ""): "utf8mb4_general_ci",
        },
        ("redis", f"This is a redis config for {PROJECT_NAME}"): {
            ("host", ""): "127.0.0.1",
            ("port", ""): 6379,
            ("username", ""): "root",
            ("password", ""): "123456",
            ("decode_responses", ""): True,
            ("ex", ""): 28 * 60 * 60 * 24,
        },
        ("rabbitmq", f"This is a rabbitmq config for {PROJECT_NAME}"): {
            ("host", ""): "127.0.0.1",
            ("port", ""): 5672,
            ("username", ""): "admin",
            ("password", ""): "123456",
            ("name", ""): PROJECT_NAME,
        },
        ("scan", f"This is a scan config for {PROJECT_NAME}"): {
            ("scan_max_task_num", ""): 50,
            ("scan_mode", f"{ScanMode.CACHE}/{ScanMode.NOCACHE}"): ScanMode.CACHE,
            ("scan_headers", ""): {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0; aiohttp) Gecko/20100101 Firefox/106.0"},
            ("scan_qps_limit", ""): 5,
            ("scan_body_size_limit", ""): 4195000,
            ("save_body_size_limit", "Max length < 131080"): 32768,
            ("skip_scan_request_extensions", ""): ['woff', 'woff2', 'ico', 'ttf', 'svg', 'otf', 'mp3', 'css'],
            ("skip_scan_response_content_types", ""): ["application/font-woff", "image/gif"],
            ("skip_scan_response_meida_types", ""): ["video", "audio"],
        },
        ("cache", f"This is a cache config for {PROJECT_NAME}"): {
            ("is_save_request_body", ""): True,
            ("is_save_response_body", ""): False,
            ("save_body_size_limit", ""): 32768,
            ("log_stored_day", ""): 30,
            ("cache_log_stored_day", ""): 2,
            ("cache_db_stored_day", ""): 1,
            ("cache_deal_time", ""): 3600,
        },
        ("platform", f"This is a platform config for {PROJECT_NAME}"): {
            ("dnslog_top_domain", ""): "",
            ("dnslog_api_url", ""): "",
            ("dnslog_api_key", ""): "",
            ("dnslog_async_time", ""): 20,
            ("dnslog_api_func", "Dnslog api function, default/celestion, and you should nano func in lib/core/api.py"): "default",
        }
    }
    return configs

def server_config():
    configs = {
        ("server", f"This is a server config for {PROJECT_NAME}"): {
            ("listen_host", ""): "0.0.0.0",
            ("listen_port", ""): 8000,
        }
    }
    return configs

def agent_config():
    configs = {
        ("agent", f"This is a agent config for {PROJECT_NAME}"): {
            ("server_host", ""): "127.0.0.1",
            ("server_port", ""): 8000,
            ("support_host", ""): "127.0.0.1",
            ("support_port", ""): 8001,
        }
    }
    return configs

def support_config():
    configs = {
        ("support", f"This is a support config for {PROJECT_NAME}"): {
            ("listen_host", ""): "0.0.0.0",
            ("listen_port", ""): 8001,
            ("server_host", ""): "127.0.0.1",
            ("server_port", ""): 8000,
        }
    }
    return configs

def manager_config():
    configs = {
        ("manager", f"This is a manager config for {PROJECT_NAME}"): {
            ("listen_host", ""): "0.0.0.0",
            ("listen_port", ""): 8002,
        }
    }
    return configs

def simple_config():
    configs = {
        ("simple", f"This is a simple config for {PROJECT_NAME}"): {
            ("listen_host", ""): "0.0.0.0",
            ("listen_port", ""): 8000,
        }
    }
    return configs

def config_parser():
    """解析配置文件，如不存在则创建"""

    config_file_list = [(BASIC_CONFIG_FILE_PATH, basic_config())]

    if 'agent' in MAIN_NAME:
        config_file_list.append((AGENT_CONFIG_FILE_PATH, agent_config()))
    elif 'support' in MAIN_NAME:
        config_file_list.append((SUPPORT_CONFIG_FILE_PATH, support_config()))
    elif 'manager' in MAIN_NAME:
        config_file_list.append((MANAGER_CONFIG_FILE_PATH, manager_config()))
    elif 'simple' in MAIN_NAME:
        config_file_list.append((SIMPLE_CONFIG_FILE_PATH, simple_config()))
    elif 'server' in MAIN_NAME:
        config_file_list.append((SERVER_CONFIG_FILE_PATH, server_config()))
    else:
        config_file_list.append((AGENT_CONFIG_FILE_PATH, agent_config()))
        config_file_list.append((SUPPORT_CONFIG_FILE_PATH, support_config()))
        config_file_list.append((MANAGER_CONFIG_FILE_PATH, manager_config()))
        config_file_list.append((SIMPLE_CONFIG_FILE_PATH, simple_config()))
        config_file_list.append((SERVER_CONFIG_FILE_PATH, server_config()))

    return parser_conf(config_file_list)