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
from lib.core.model import Cache
from lib.core.model import Addon
from lib.core.model import Vul
from lib.util.util import get_timestamp
from lib.util.util import get_time_str
from lib.util.util import get_time
from lib.core.enums import ApiStatus
from lib.hander.basehander import fix_response
from lib.hander.basehander import save_sql
from lib.hander.basehander import login_check

mod = Blueprint('cache', __name__, url_prefix=f"{PREFIX_URL}/manger/cache")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Cache'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/cache/cache.html', **ctx)


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
    keyword = request.json.get('keyword', '')
    url = request.json.get('url', '')
    condition = (1 == 1)
    if keyword != '':
        condition = and_(condition, Cache.keyword.like('%' + keyword + '%'))

    if url != '':
        condition = and_(condition, Cache.url.like('%' + url + '%'))


    if per_page == 'all':
        for row in db.session.query(Cache.id, Cache.url, Cache.keyword, Cache.response_status_code, Cache.update_time).filter(condition).all():
            id, url, keyword, response_status_code, update_time = row
            dic = {
                'id': id,
                "url": url,
                "keyword": keyword,
                "response_status_code": response_status_code,
                'update_time': get_time_str(update_time),
            }
            response['data']['res'].append(dic)
    else:
        for row in db.session.query(Cache.id, Cache.url, Cache.keyword, Cache.response_status_code, Cache.update_time).filter(condition).order_by(Cache.update_time.desc()).paginate(page=page, per_page=per_page).items:
            id, url, keyword, response_status_code, update_time = row
            dic = {
                'id': id,
                "url": url,
                "keyword": keyword,
                "response_status_code": response_status_code,
                'update_time': get_time_str(update_time),
            }
            response['data']['res'].append(dic)
    response['data']['total'] = db.session.query(Cache.id).filter(condition).count()
    return response

@mod.route('/clear_all', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_all():
    response = {'data': {'res': []}}
    condition = (1 == 1)
    condition = and_(condition)
    db.session.query(Cache).filter(condition).delete(synchronize_session=False)
    return response


@mod.route('/clear_3day_old', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_3day_old():
    response = {'data': {'res': []}}
    delete_time = get_time(get_timestamp() - 60 * 60 * 24 * 3)
    condition = (1 == 1)
    condition = and_(condition, Cache.update_time <= delete_time)
    db.session.query(Cache).filter(condition).delete(synchronize_session=False)
    return response

@mod.route('/detail', methods=['POST', 'GET'])
@login_check
@fix_response
def detail():
    response = {'data': {'res': []}}
    cache_id = request.json.get('id', '')
    if cache_id != '':
        cache = db.session.query(Cache).filter(Cache.id == cache_id).first()
        if cache:
            cache_dic = {}
            url_temp = cache.url[cache.url.replace('://', '___').index('/'):]
            request_headers = json.loads(cache.request_headers) if cache.request_headers else {}

            cache_dic['url'] = cache.url
            cache_dic['request'] = cache.method + ' ' + url_temp + ' ' + cache.request_http_version + '\r\n'
            cache_dic['request'] += '\r\n'.join([key + ': ' + value for key, value in request_headers.items()])
            cache_dic['request'] += '\r\n\r\n'
            try:
                cache_dic['request'] += bytes.decode(cache.request_content) if cache.request_content else ''
            except:
                pass
            if cache.response_status_code and cache.response_status_code !=0 :
                response_headers = json.loads(cache.response_headers) if cache.response_headers else {}
                cache_dic['response'] = cache.response_http_version + ' ' + str(cache.response_status_code) + ' ' + cache.response_reason + '\r\n'
                cache_dic['response'] += '\r\n'.join([key + ': ' + value for key, value in response_headers.items()])
                cache_dic['response'] += '\r\n\r\n'
                try:
                    cache_dic['response'] += bytes.decode(cache.response_content) if cache.response_content else ''
                except:
                    pass
            response['data']['res'].append(cache_dic)
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    cache_id = request.json.get('id', '')
    cache_ids = request.json.get('ids', '')
    if cache_id != '' or cache_ids != '':
        if cache_id != '':
            cache_id = int(cache_id)
            cache = db.session.query(Cache).filter(Cache.id == cache_id).first()
            if cache:
                db.session.delete(cache)
                db.session.commit()
                response['data']['res'].append(cache_id)
        if cache_ids != '':
            try:
                for cache_id in cache_ids.split(','):
                    cache_id = int(cache_id.replace(' ', ''))
                    cache = db.session.query(Cache).filter(Cache.id == cache_id).first()
                    if cache:
                        db.session.delete(cache)
                        db.session.commit()
                        response['data']['res'].append(cache_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/insert_vul', methods=['POST', 'GET'])
@login_check
@fix_response
def insert_vul():
    response = {'data': {'res': []}}
    cache_id = request.json.get('id', '')
    cache_ids = request.json.get('ids', '')
    if cache_id != '' or cache_ids != '':
        if cache_id != '':
            cache_id = int(cache_id)
            cache = db.session.query(Cache).filter(Cache.id == cache_id).first()
            if cache:
                scheme = cache.scheme
                method = cache.method
                host = cache.host
                port = cache.port
                url = cache.url
                request_headers = cache.request_headers
                request_content_length = cache.request_content_length
                response_headers = cache.response_headers
                response_http_version = cache.response_http_version
                request_content = cache.request_content
                response_content_type = cache.response_content_type
                response_content = cache.response_content
                response_status_code = cache.response_status_code
                request_http_version = cache.request_http_version
                websocket_content = cache.websocket_content
                websocket_type = cache.websocket_type
                response_content_length = cache.response_content_length
                response_reason = cache.response_reason
                update_time = cache.update_time
                detail = f"Add from cache, Keyword: {cache.keyword}"
                addon = db.session.query(Addon).filter(Addon.addon_path == cache.addon_path).first()
                addon_id = addon.id if addon else None
                vul = db.session.query(Vul).filter(and_(Vul.url == url, Vul.addon_id == addon_id, Vul.method == method)).first()
                if vul:
                    vul.scheme = cache.scheme
                    vul.method = cache.method
                    vul.host = cache.host
                    vul.port = cache.port
                    vul.url = cache.url
                    vul.request_headers = cache.request_headers
                    vul.request_content_length = cache.request_content_length
                    vul.response_headers = cache.response_headers
                    vul.response_http_version = cache.response_http_version
                    vul.request_content = cache.request_content
                    vul.response_content_type = cache.response_content_type
                    vul.response_content = cache.response_content
                    vul.response_status_code = cache.response_status_code
                    vul.request_http_version = cache.request_http_version
                    vul.response_content_length = cache.response_content_length
                    vul.response_reason = cache.response_reason
                    vul.websocket_content = cache.websocket_content
                    vul.websocket_type = cache.websocket_type
                    vul.update_time = cache.update_time
                    vul.detail = f"Add from cache, Keyword: {cache.keyword}"
                else:
                    vul = Vul(
                        scheme=scheme, method=method, host=host, port=port, url=url,
                        request_headers=request_headers, request_content_length=request_content_length,
                        request_content=request_content, response_headers=response_headers,
                        response_http_version=response_http_version, websocket_type=websocket_type,
                        response_content_length=response_content_length, websocket_content=websocket_content,
                        request_http_version=request_http_version,
                        response_status_code=response_status_code, response_content_type=response_content_type,
                        response_reason=response_reason, response_content=response_content,
                        update_time=update_time, addon_id=addon_id, detail=detail
                    )
                if save_sql(vul):
                    response['data']['res'].append(addon_id)
        if cache_ids != '':
            try:
                for cache_id in cache_ids.split(','):
                    cache_id = int(cache_id.replace(' ', ''))
                    cache = db.session.query(Cache).filter(Cache.id == cache_id).first()
                    if cache:
                        scheme = cache.scheme
                        method = cache.method
                        host = cache.host
                        port = cache.port
                        url = cache.url
                        request_headers = cache.request_headers
                        request_content_length = cache.request_content_length
                        response_headers = cache.response_headers
                        response_http_version = cache.response_http_version
                        request_content = cache.request_content
                        response_content_type = cache.response_content_type
                        response_content = cache.response_content
                        response_status_code = cache.response_status_code
                        websocket_content = cache.websocket_content
                        websocket_type = cache.websocket_type
                        request_http_version = cache.request_http_version
                        response_content_length = cache.response_content_length
                        response_reason = cache.response_reason
                        update_time = cache.update_time
                        detail = f"Add from cache, Keyword: {cache.keyword}"
                        addon = db.session.query(Addon).filter(Addon.addon_path == cache.addon_path).first()
                        addon_id = addon.addon_id if addon else None
                        vul = db.session.query(Vul).filter(and_(Vul.url == url, Vul.addon_id == addon_id, Vul.method == method)).first()
                        if vul:
                            vul.scheme = cache.scheme
                            vul.method = cache.method
                            vul.host = cache.host
                            vul.port = cache.port
                            vul.url = cache.url
                            vul.request_headers = cache.request_headers
                            vul.request_content_length = cache.request_content_length
                            vul.response_headers = cache.response_headers
                            vul.response_http_version = cache.response_http_version
                            vul.request_content = cache.request_content
                            vul.response_content_type = cache.response_content_type
                            vul.response_content = cache.response_content
                            vul.response_status_code = cache.response_status_code
                            vul.request_http_version = cache.request_http_version
                            vul.response_content_length = cache.response_content_length
                            vul.response_reason = cache.response_reason
                            vul.websocket_content = cache.websocket_content
                            vul.websocket_type = cache.websocket_type
                            vul.update_time = cache.update_time
                            vul.detail = f"Add from cache, Keyword: {cache.keyword}"
                        else:
                            vul = Vul(
                                scheme=scheme, method=method, host=host, port=port, url=url,
                                request_headers=request_headers, request_content_length=request_content_length,
                                request_content=request_content, response_headers=response_headers,
                                response_http_version=response_http_version, websocket_type=websocket_type,
                                response_content_length=response_content_length, websocket_content=websocket_content,
                                request_http_version=request_http_version,
                                response_status_code=response_status_code, response_content_type=response_content_type,
                                response_reason=response_reason, response_content=response_content,
                                update_time=update_time, addon_id=addon_id, detail=detail
                            )
                        if save_sql(vul):
                            response['data']['res'].append(addon_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST