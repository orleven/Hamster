#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven


from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from lib.core.enums import ApiStatus
from lib.hander import db
from lib.core.env import *
from lib.core.model import DNSLog
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check
from lib.util.util import get_timestamp
from lib.util.util import get_time

mod = Blueprint('dnslog', __name__, url_prefix=f"{PREFIX_URL}/manger/dnslog")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'DNSLog'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/cache/dnslog.html', **ctx)

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
    ip = request.json.get('ip', '')
    condition = (1 == 1)
    if keyword != '':
        condition = and_(condition, DNSLog.keyword.like('%' + keyword + '%'))

    if ip != '':
        condition = and_(condition, DNSLog.ip.like('%' + ip + '%'))

    if per_page == 'all':
        for row in db.session.query(DNSLog).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(DNSLog).filter(condition).order_by(DNSLog.update_time.desc()).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(DNSLog).filter(condition).count()
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
            packet = db.session.query(DNSLog).filter(DNSLog.id == id).first()
            if packet:
                db.session.delete(packet)
                db.session.commit()
                response['data']['res'].append(id)
        if ids != '':
            try:
                for id in ids.split(','):
                    id = id.replace(' ', '')
                    packet = db.session.query(DNSLog).filter(DNSLog.id == id).first()
                    if packet:
                        db.session.delete(packet)
                        db.session.commit()
                        response['data']['res'].append(id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/clear_all', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_all():
    response = {'data': {'res': []}}
    condition = (1 == 1)
    db.session.query(DNSLog).filter(condition).delete(synchronize_session=False)
    return response

@mod.route('/clear_3day_old', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_3day_old():
    response = {'data': {'res': []}}
    delete_time = get_time(get_timestamp() - 60 * 60 * 24 * 3)
    condition = (1 == 1)
    condition = and_(condition, DNSLog.update_time <= delete_time)
    db.session.query(DNSLog).filter(condition).delete(synchronize_session=False)
    return response