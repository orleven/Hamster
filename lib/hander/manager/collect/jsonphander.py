#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import json
from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from lib.core.env import *
from lib.hander import db
from lib.core.model import CollectJsonp
from lib.core.enums import ApiStatus
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('jsonp', __name__, url_prefix=f"{PREFIX_URL}/manger/jsonp")


@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Jsonp'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/collect/jsonp.html', **ctx)

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
    url = request.json.get('url', '')
    request_headers = request.json.get('request_headers', '')
    request_content = request.json.get('request_content', '')
    method = request.json.get('method', '')
    response_status_code = request.json.get('status_code', '')
    condition = (1 == 1)

    if request_content != '':
        condition = and_(condition, CollectJsonp.request_content.like(bytes('%' + request_content + '%', encoding="utf8")))

    if url != '':
        condition = and_(condition, CollectJsonp.url.like('%' + url + '%'))

    if method != '':
        condition = and_(condition, CollectJsonp.method.like('%' + method + '%'))

    if response_status_code != '':
        condition = and_(condition, CollectJsonp.response_status_code.like('%' + response_status_code + '%'))

    if request_headers != '':
        condition = and_(condition, CollectJsonp.request_headers.like('%' + request_headers + '%'))

    if per_page == 'all':
        for row in db.session.query(CollectJsonp).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(CollectJsonp).filter(condition).order_by(CollectJsonp.update_time.desc()).paginate(page=page,
                                                                                               per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(CollectJsonp).filter(condition).count()
    return response


@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    id = request.json.get('id', '')
    ids = request.json.get('ids', '')
    if id != '' or ids != '':
        if id != '':
            jsonp = db.session.query(CollectJsonp).filter(CollectJsonp.id == id).first()
            if jsonp:
                db.session.delete(jsonp)
                db.session.commit()
                response['data']['res'].append(id)
        if ids != '':
            try:
                for id in ids.split(','):
                    id = id.replace(' ', '')
                    jsonp = db.session.query(CollectJsonp).filter(CollectJsonp.id == id).first()
                    if jsonp:
                        db.session.delete(jsonp)
                        db.session.commit()
                        response['data']['res'].append(id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/detail', methods=['POST', 'GET'])
@login_check
@fix_response
def detail():
    response = {'data': {'res': []}}
    id = request.json.get('id', '')
    if id != '':
        jsonp = db.session.query(CollectJsonp).filter(CollectJsonp.id == id).first()
        if jsonp:
            jsonp_dic = {}
            request_headers = json.loads(jsonp.request_headers)
            response_headers = json.loads(jsonp.response_headers)
            url_temp = jsonp.url[jsonp.url.replace('://', '___').index('/'):]
            jsonp_dic['url'] = jsonp.url
            jsonp_dic['request'] = jsonp.method + ' ' + url_temp + ' ' + jsonp.request_http_version + '\r\n'
            jsonp_dic['request'] += '\r\n'.join([key + ': ' + value for key, value in request_headers.items()])
            jsonp_dic['request'] += '\r\n\r\n'
            try:
                jsonp_dic['request'] += bytes.decode(jsonp.request_content) if jsonp.request_content else ''
            except:
                pass
            jsonp_dic['response'] = jsonp.response_http_version + ' ' + str(jsonp.response_status_code) + ' ' + jsonp.response_reason + '\r\n'
            jsonp_dic['response'] += '\r\n'.join([key + ': ' + value for key, value in response_headers.items()])
            jsonp_dic['response'] += '\r\n\r\n'
            try:
                jsonp_dic['response'] += bytes.decode(jsonp.response_content) if jsonp.response_content else ''
            except:
                pass
            response['data']['res'].append(jsonp_dic)
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
