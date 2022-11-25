#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import json
from flask import request
from flask import render_template
from flask import session
from flask import Blueprint
from sqlalchemy import and_
from lib.hander import db
from lib.core.env import *
from lib.core.model import Vul
from lib.core.model import Addon
from lib.util.util import get_time
from lib.hander.basehander import save_sql
from lib.core.enums import VulLevel
from lib.core.enums import ApiStatus
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('vul', __name__, url_prefix=f"{PREFIX_URL}/vul")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Vulnerability'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['vul_level'] = VulLevel
    return render_template('manager/vulnerability.html', **ctx)

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
    name = request.json.get('name', '')
    url = request.json.get('url', '')
    level = request.json.get('level', '')
    detail = request.json.get('detail', '')
    condition = (1 == 1)
    if level != '':
        if level not in [VulLevel.CRITICAL, VulLevel.HIGH, VulLevel.INFO, VulLevel.MEDIUM, VulLevel.LOWER]:
            return ApiStatus.ERROR_INVALID_INPUT
        condition = and_(condition, Addon.level == level)

    if name != '':
        condition = and_(condition, Addon.addon_name.like('%' + name + '%'))

    if url != '':
        condition = and_(condition, Vul.url.like('%' + url + '%'))

    if detail != '':
        condition = and_(condition, Vul.detail.like('%' + detail + '%'))

    if per_page == 'all':
        for row in db.session.query(Vul).join(Addon, Vul.addon_id == Addon.id).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(Vul).join(Addon, Vul.addon_id == Addon.id).filter(condition).order_by(
                Vul.update_time.desc()).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(Vul).join(Addon, Vul.addon_id == Addon.id).filter(condition).count()
    return response

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    vul_id = request.json.get('id', '')
    vul_ids = request.json.get('ids', '')
    if vul_id != '' or vul_ids != '':
        if vul_id != '':
            vul_id = int(vul_id)
            vul = db.session.query(Vul).filter(Vul.id == vul_id).first()
            if vul:
                db.session.delete(vul)
                db.session.commit()
                response['data']['res'].append(vul_id)
        if vul_ids != '':
            try:
                for vul_id in vul_ids.split(','):
                    vul_id = int(vul_id.replace(' ', ''))
                    vul = db.session.query(Vul).filter(Vul.id == vul_id).first()
                    if vul:
                        db.session.delete(vul)
                        db.session.commit()
                        response['data']['res'].append(vul_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    vul_id = request.json.get('id', '')
    vul_name = request.json.get('vul_name', '')
    detail = request.json.get('detail', '')
    mark = request.json.get('mark', '')
    if vul_id != '':
        vul_id = int(vul_id)
        vul = db.session.query(Vul).filter(Vul.id == vul_id).first()
        if vul:
            vul.mark = mark
            vul.vul_name = vul_name
            vul.detail = detail
            vul.update_time = get_time()
            save_sql(vul)
            return {'data': {'res': [vul_id]}}
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/detail', methods=['POST', 'GET'])
@login_check
@fix_response
def detail():
    response = {'data': {'res': []}}
    vul_id = request.json.get('id', '')
    if vul_id != '':
        vul = db.session.query(Vul).filter(Vul.id == vul_id).first()
        if vul:
            vul_dic = {}
            url_temp = vul.url[vul.url.replace('://', '___').index('/'):]
            request_headers = json.loads(vul.request_headers) if vul.request_headers else {}

            vul_dic['url'] = vul.url
            vul_dic['request'] = vul.method + ' ' + url_temp + ' ' + vul.request_http_version + '\r\n'
            vul_dic['request'] += '\r\n'.join([key + ': ' + value for key, value in request_headers.items()])
            vul_dic['request'] += '\r\n\r\n'
            try:
                vul_dic['request'] += bytes.decode(vul.request_content) if vul.request_content else ''
            except:
                pass

            if vul.response_status_code and vul.response_status_code != 0:
                response_headers = json.loads(vul.response_headers) if vul.response_headers else {}
                vul_dic['response'] = vul.response_http_version + ' ' + str(
                    vul.response_status_code) + ' ' + vul.response_reason + '\r\n'
                vul_dic['response'] += '\r\n'.join([key + ': ' + value for key, value in response_headers.items()])
                vul_dic['response'] += '\r\n\r\n'
                try:
                    vul_dic['response'] += bytes.decode(vul.response_content) if vul.response_content else ''
                except:
                    pass
            response['data']['res'].append(vul_dic)
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST