#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from lib.core.env import *
from lib.core.model import Addon
from lib.core.enums import AddonType
from lib.core.enums import ApiStatus
from lib.core.enums import VulLevel
from lib.core.enums import VulType
from lib.core.enums import AddonEnable
from lib.hander import db
from lib.hander.basehander import fix_response
from lib.hander.basehander import save_sql
from lib.hander.basehander import login_check
from lib.util.util import get_time


mod = Blueprint('addon', __name__, url_prefix=f"{PREFIX_URL}/manger/addon")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Addon'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['addon_type'] = AddonType
    ctx['vul_type'] = VulType
    ctx['level'] = VulLevel
    ctx['enable'] = AddonEnable
    ctx['root_addon_path'] = ADDON_PATH
    return render_template('manager/system/addon.html', **ctx)



@mod.route('/list', methods=['POST', 'GET'])
@login_check
@fix_response
def list():
    response = {
        'data': {
            'res': [],
            'total': 0,
        }
    }
    page = request.json.get('page', 1)
    per_page = request.json.get('per_page', 10)
    addon_path = request.json.get('addon_path', '')
    addon_name = request.json.get('addon_name', '')
    vul_name = request.json.get('vul_name', '')
    addon_type = request.json.get('addon_type', '')
    enable = request.json.get('enable', '')

    condition = (1 == 1)
    
    if addon_path != '':
        condition = and_(condition, Addon.addon_path.like('%' + addon_path + '%'))

    if addon_name != '':
        condition = and_(condition, Addon.addon_name.like('%' + addon_name + '%'))

    if vul_name != '':
        condition = and_(condition, Addon.vul_name.like('%' + vul_name + '%'))

    if enable != '' and isinstance(enable, bool):
        condition = and_(condition, Addon.enable == enable)

    if addon_type != '' and addon_type in [AddonType.FILE_ONCE, AddonType.DIR_ALL, AddonType.HOST_ONCE, AddonType.URL_ONCE]:
        condition = and_(condition, Addon.addon_type == addon_type)

    if per_page == 'all':
        for row in db.session.query(Addon).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(Addon).filter(condition).order_by(Addon.update_time.desc()).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(Addon).filter(condition).count()
    return response


@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    addon_id = request.json.get('id', '')
    addon_ids = request.json.get('ids', '')
    if addon_id != '' or addon_ids != '':
        if addon_id != '':
            addon_id = int(addon_id)
            addon = db.session.query(Addon).filter(Addon.id == addon_id).first()
            if addon:
                db.session.delete(addon)
                db.session.commit()
                response['data']['res'].append(addon_id)
        if addon_ids != '':
            try:
                for addon_id in addon_ids.split(','):
                    addon_id = int(addon_id.replace(' ', ''))
                    addon = db.session.query(Addon).filter(Addon.id == addon_id).first()
                    if addon:
                        db.session.delete(addon)
                        db.session.commit()
                        response['data']['res'].append(addon_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    id = int(request.json.get('id', ''))
    vul_type = request.json.get('vul_type', '')
    addon_type = request.json.get('addon_type', '')
    mark = request.json.get('mark', '')
    enable = request.json.get('enable', '')
    level = request.json.get('level', '')
    description = request.json.get('description', '')
    scopen = request.json.get('scopen', '')
    impact = request.json.get('impact', '')
    suggestions = request.json.get('suggestions', '')
    vul_name = request.json.get('vul_name', '')

    addon = db.session.query(Addon).filter_by(id=id).first()
    if addon:
        if isinstance(enable, bool):
            addon.enable = enable
        if level in [VulLevel.NONE, VulLevel.INFO, VulLevel.CRITICAL, VulLevel.MEDIUM, VulLevel.HIGH, VulLevel.LOWER]:
            addon.level = level
        if addon_type in [AddonType.FILE_ONCE, AddonType.DIR_ALL, AddonType.HOST_ONCE, AddonType.URL_ONCE]:
            addon.addon_type = addon_type
        if vul_type in [VulType.SSRF, VulType.SQL_Inject, VulType.XSS, VulType.INFO, VulType.RCE, VulType.XXE, VulType.SENSITIVE_INFO, VulType.BYPASS_AUTHORITY, VulType.UNAUTHORIZED_ACCESS, VulType.INFO_FILE, VulType.WEAKPASS, VulType.OTHER, VulType.NONE]:
            addon.vul_type = vul_type
        addon.level = level
        addon.vul_name = vul_name
        addon.scopen = scopen
        addon.suggestions = suggestions
        addon.impact = impact
        addon.update_time = get_time()
        addon.mark = mark
        addon.description = description
        if save_sql(addon):
            return {'user': {'res': [addon.id]}}
        else:
            return ApiStatus.ERROR

    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/detail', methods=['POST', 'GET'])
@login_check
@fix_response
def detail():
    response = {
        'data': {
            'res': [],
            'total': 0,
        }
    }
    addons_info_res = {}
    addon_id = int(request.json.get('id', ''))
    addon = db.session.query(Addon).filter(Addon.id == addon_id).first()
    if addon:
        path = os.path.join(ROOT_PATH, addon.addon_path)
        try:
            with open(path, 'r') as f:
                content = ''.join([x for x in f.readlines()])
        except:
            content = ''
        addons_info_res['content'] = content
        response['data']['res'].append(addons_info_res)
    response['data']['total'] = len(response['data']['res'])
    return response
