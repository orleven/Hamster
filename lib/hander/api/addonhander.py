#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import request
from flask import Blueprint
from flask import send_file
from lib.core.env import *
from lib.core.enums import ApiStatus
from lib.util.addonutil import import_addon_file
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('api_addon', __name__, url_prefix=f"{PREFIX_URL}/api/addon")

@mod.route('/list', methods=['POST', 'GET'])
@login_check
@fix_response
def list():
    """获取addon信息"""
    response = {
        'data': {
            'res': [],
        }
    }
    addon_path = request.json.get('addon_path', '')
    if addon_path != '':
        addons = import_addon_file(addon_path)
    else:
        addons = import_addon_file(os.path.join(ADDON_PATH))

    for i in range(0, len(addons)):
        response['data']['res'].append(addons[i].info())
    response['data']['total'] = len(addons)
    return response

@mod.route('/async', methods=['POST', 'GET'])
@login_check
def sync():
    """获取addon文件"""
    addon_path = request.json.get('addon_path', '')
    addons = import_addon_file(addon_path)

    if len(addons) == 1:
        path = os.path.join(ROOT_PATH, addons[0].info()["addon_path"])
        return send_file(path, mimetype='application/octet-stream', attachment_filename=addons[0].info()["addon_file_name"], as_attachment=True)
    return ApiStatus.ERROR_INVALID_INPUT_ADDON_NAME