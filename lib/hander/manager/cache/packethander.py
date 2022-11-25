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
from lib.core.model import Packet
from lib.core.enums import ApiStatus
from lib.util.util import get_timestamp
from lib.util.util import get_time
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('packet', __name__, url_prefix=f"{PREFIX_URL}/manger/packet")


@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Packet'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/cache/packet.html', **ctx)

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
        condition = and_(condition, Packet.request_content.like(bytes('%' + request_content + '%', encoding="utf8")))

    if url != '':
        condition = and_(condition, Packet.url.like('%' + url + '%'))

    if method != '':
        condition = and_(condition, Packet.method.like('%' + method + '%'))

    if response_status_code != '':
        condition = and_(condition, Packet.response_status_code.like('%' + response_status_code + '%'))

    if request_headers != '':
        condition = and_(condition, Packet.request_headers.like('%' + request_headers + '%'))

    if per_page == 'all':
        for row in db.session.query(Packet).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(Packet).filter(condition).order_by(Packet.update_time.desc()).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(Packet).filter(condition).count()
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
            packet = db.session.query(Packet).filter(Packet.id == id).first()
            if packet:
                db.session.delete(packet)
                db.session.commit()
                response['data']['res'].append(id)
        if ids != '':
            try:
                for id in ids.split(','):
                    id = id.replace(' ', '')
                    packet = db.session.query(Packet).filter(Packet.id == id).first()
                    if packet:
                        db.session.delete(packet)
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
        packet = db.session.query(Packet).filter(Packet.id == id).first()
        if packet:
            packet_dic = {}
            request_headers = json.loads(packet.request_headers)
            response_headers = json.loads(packet.response_headers)
            url_temp = packet.url[packet.url.replace('://', '___').index('/'):]
            packet_dic['url'] = packet.url
            packet_dic['request'] = packet.method + ' ' + url_temp + ' ' + packet.request_http_version + '\r\n'
            packet_dic['request'] += '\r\n'.join([key + ': ' + value for key, value in request_headers.items()])
            packet_dic['request'] += '\r\n\r\n'
            try:
                packet_dic['request'] += bytes.decode(packet.request_content) if packet.request_content else ''
            except:
                pass
            packet_dic['response'] = packet.response_http_version + ' ' + str(packet.response_status_code) + ' ' + packet.response_reason + '\r\n'
            packet_dic['response'] += '\r\n'.join([key + ': ' + value for key, value in response_headers.items()])
            packet_dic['response'] += '\r\n\r\n'
            try:
                packet_dic['response'] += bytes.decode(packet.response_content) if packet.response_content else ''
            except:
                pass
            response['data']['res'].append(packet_dic)
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/clear_all', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_all():
    response = {'data': {'res': []}}
    condition = (1 == 1)
    db.session.query(Packet).filter(condition).delete(synchronize_session=False)
    return response

@mod.route('/clear_3day_old', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_3day_old():
    response = {'data': {'res': []}}
    delete_time = get_time(get_timestamp() - 60 * 60 * 24 * 3)
    condition = (1 == 1)
    condition = and_(condition, Packet.update_time <= delete_time)
    db.session.query(Packet).filter(condition).delete(synchronize_session=False)
    return response