#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import os
import json
import configparser
from attribdict import AttribDict

def load_conf(path):
    """加载配置文件"""

    config = AttribDict()
    cf = configparser.ConfigParser()
    cf.read(path)
    sections = cf.sections()
    for section in sections:
        config[section] = AttribDict()
        for option in cf.options(section):
            value = cf.get(section, option)
            try:
                if value.startswith("{") and value.endswith("}") or value.startswith("[") and value.endswith("]"):
                    value = json.loads(value)
                elif value.lower() == "false":
                    value = False
                elif value.lower() == "true":
                    value = True
                else:
                    value = int(value)
            except Exception as e:
                pass
            config[section][option] = value
    return config


def init_conf(path, configs):
    """初始化配置文件"""

    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    cf = configparser.ConfigParser(allow_no_value=True)
    for (section, section_comment), section_value in configs.items():
        cf.add_section(section)

        if section_comment and section_comment != "":
            cf.set(section, fix_comment_content(f"{section_comment}\r\n"))

        for (key, key_comment), key_value in section_value.items():
            if key_comment and key_comment != "":
                cf.set(section, fix_comment_content(key_comment))
            if isinstance(key_value, dict) or isinstance(key_value, list):
                key_value = json.dumps(key_value)
            else:
                key_value = str(key_value)
            cf.set(section, key, f"{key_value}\r\n")

    with open(path, 'w+') as configfile:
        cf.write(configfile)


def fix_comment_content(content):
    """按照80个字符一行就行格式化处理"""

    text = f'; '
    for i in range(0, len(content)):
        if i != 0 and i % 80 == 0:
            text += '\r\n; '
        text += content[i]
    return text


def parser_conf(config_file_list):
    """解析配置文件，如不存在则创建"""

    config = dict()
    flag = True
    for _config_file, _config in config_file_list:

        if not os.path.exists(_config_file):
            flag = False
            init_conf(_config_file, _config)
            print(f"Please set the config in {_config_file}...")

        temp_conf = load_conf(_config_file)
        config.update(temp_conf.as_dict())

    if not flag:
        exit()

    return AttribDict(config)
