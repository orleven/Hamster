#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from sqlalchemy import or_
from lib.core.model import Log
from lib.core.model import User
from lib.hander import db
from lib.core.env import *
from lib.util.util import get_timestamp
from lib.util.util import get_time
from lib.core.enums import ApiStatus
from lib.core.enums import WebLogType
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('log', __name__, url_prefix=f"{PREFIX_URL}/manger/log")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Log'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['log_type'] = WebLogType
    return render_template('manager/system/log.html', **ctx)


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
    update_time = request.json.get('update_time', '')
    url = request.json.get('url', '')
    ip = request.json.get('ip', '')
    user = request.json.get('user', '')
    description = request.json.get('description', '')
    condition = (1 == 1)
    if update_time != '':
        condition = and_(condition, Log.update_time.like('%' + update_time + '%'))

    if description != '':
        condition = and_(condition, Log.description.like('%' + description + '%'))

    if url != '':
        condition = and_(condition, Log.url.like('%' + url + '%'))

    if user != '':
        users = db.session.query(User).filter(User.username.like('%' + user + '%')).all()
        condition_user = (1 == 2)
        for user in users:
            condition_user = or_(condition_user, Log.user_id == user.id)
        condition = and_(condition, condition_user)

    if ip != '':
        condition = and_(condition, Log.body.like('%' + ip + '%'))

    if per_page == 'all':
        for row in db.session.query(Log).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(Log).filter(condition).order_by(Log.update_time.desc()).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(Log).filter(condition).count()
    return response

@mod.route('/clear_all', methods=['POST', 'GET'])
@login_check
@fix_response
def clear_all():
    response = {'data': {'res': []}}
    delete_time = get_time(get_timestamp())
    condition = (1 == 1)
    condition = and_(condition, Log.update_time <= delete_time)
    db.session.query(Log).filter(condition).delete(synchronize_session=False)
    return response

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    log_id = request.json.get('id', '')
    log_ids = request.json.get('ids', '')
    if log_id != '' or log_ids != '':
        if log_id != '':
            log_id = int(log_id)
            db.session.query(Log).filter(Log.id == log_id).delete(synchronize_session=False)
            return response
        if log_ids != '':
            try:
                for log_id in log_ids.split(','):
                    log_id = int(log_id.replace(' ', ''))
                    db.session.query(Log).filter(Log.id == log_id).delete(synchronize_session=False)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST