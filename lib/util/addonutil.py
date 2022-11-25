#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
import importlib.util
import traceback

from lib.core.env import *
from lib.core.g import log


def import_addon_file(addons_path=None):
    """载入addon"""

    addon_list = []
    addon_path_list = []
    if addons_path:
        _len = len(ROOT_PATH) + 1
        if os.path.isdir(addons_path):
            for parent, dirnames, filenames in os.walk(addons_path, followlinks=True):
                for each in filenames:
                    if '__init__' in each or each.startswith('.') or not each.endswith('.py') or each == "init.py":
                        continue

                    addon_path = '.'.join(re.split('[\\\\/]', os.path.join(parent, each)[_len:-3]))
                    addon_path_list.append(addon_path)
        else:
            if addons_path.startswith(ROOT_PATH):
                addons_path = addons_path[_len:]
            if addons_path.endswith('.py'):
                addons_path = addons_path[: -3]
            addon_path = '.'.join(re.split('[\\\\/]', addons_path))
            addon_path_list.append(addon_path)

        addon_path_list.sort()

        for addon_path in addon_path_list:
            addon = import_script_file(addon_path)
            if addon:
                try:
                    addon = addon.Addon()
                    addon_path = addon.info().get("addon_path", None)
                    log.debug(f"Import addon file, addon: {addon_path}")
                except Exception as e:
                    log.error(f'Error import addon file, addon: {addons_path}, error: {str(e)}')
                else:
                    addon_list.append(addon)
    return addon_list


def import_script_file(script_file=None):
    """载入script"""

    try:
        module_spec = importlib.util.find_spec(script_file)
    except:
        log.error(f'Error load addon, addon: {script_file}, error: module spec error')
        return None
    else:
        if module_spec:
            try:
                module = importlib.import_module(script_file)
                module = importlib.reload(module)
                if 'Addon' not in dir(module):
                    log.error(f'Error import script file, addon: {script_file}, error: can\'t find Addon class.')
                else:
                    return module
            except Exception as e:
                traceback.print_exc()
                log.error(f'Error import script file, addon: {script_file}, error: {str(e)}')
        else:
            log.error(f'Error import script file, addon: {script_file}, error: module spec error')
    return None
