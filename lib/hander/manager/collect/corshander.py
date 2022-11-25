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
from lib.core.model import CollectCORS
from lib.core.enums import ApiStatus
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('cors', __name__, url_prefix=f"{PREFIX_URL}/manger/cors")


@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'CORS'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/collect/cors.html', **ctx)


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
        condition = and_(condition, CollectCORS.request_content.like(bytes('%' + request_content + '%', encoding="utf8")))

    if url != '':
        condition = and_(condition, CollectCORS.url.like('%' + url + '%'))

    if method != '':
        condition = and_(condition, CollectCORS.method.like('%' + method + '%'))

    if response_status_code != '':
        condition = and_(condition, CollectCORS.response_status_code.like('%' + response_status_code + '%'))

    if request_headers != '':
        condition = and_(condition, CollectCORS.request_headers.like('%' + request_headers + '%'))

    if per_page == 'all':
        for row in db.session.query(CollectCORS).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(CollectCORS).filter(condition).order_by(CollectCORS.update_time.desc()).paginate(page=page,
                                                                                               per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(CollectCORS).filter(condition).count()
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
            cors = db.session.query(CollectCORS).filter(CollectCORS.id == id).first()
            if cors:
                db.session.delete(cors)
                db.session.commit()
                response['data']['res'].append(id)
        if ids != '':
            try:
                for id in ids.split(','):
                    id = id.replace(' ', '')
                    cors = db.session.query(CollectCORS).filter(CollectCORS.id == id).first()
                    if cors:
                        db.session.delete(cors)
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
        cors = db.session.query(CollectCORS).filter(CollectCORS.id == id).first()
        if cors:
            cors_dic = {}
            request_headers = json.loads(cors.request_headers)
            response_headers = json.loads(cors.response_headers)
            url_temp = cors.url[cors.url.replace('://', '___').index('/'):]
            cors_dic['url'] = cors.url
            cors_dic['request'] = cors.method + ' ' + url_temp + ' ' + cors.request_http_version + '\r\n'
            cors_dic['request'] += '\r\n'.join([key + ': ' + value for key, value in request_headers.items()])
            cors_dic['request'] += '\r\n\r\n'
            try:
                cors_dic['request'] += bytes.decode(cors.request_content) if cors.request_content else ''
            except:
                pass
            cors_dic['response'] = cors.response_http_version + ' ' + str(cors.response_status_code) + ' ' + cors.response_reason + '\r\n'
            cors_dic['response'] += '\r\n'.join([key + ': ' + value for key, value in response_headers.items()])
            cors_dic['response'] += '\r\n\r\n'
            try:
                cors_dic['response'] += bytes.decode(cors.response_content) if cors.response_content else ''
            except:
                pass
            response['data']['res'].append(cors_dic)
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
