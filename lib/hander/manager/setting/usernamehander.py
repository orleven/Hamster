#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from lib.hander import db
from lib.core.env import *
from lib.core.model import DictUsername
from lib.core.enums import ApiStatus
from lib.util.util import get_time
from lib.core.g import conf
from lib.hander.basehander import save_sql
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('username', __name__, url_prefix=f"{PREFIX_URL}/manger/username")


@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Username'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/setting/username.html', **ctx)


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
    value = request.json.get('value', '')
    condition = (1 == 1)

    if value != '':
        condition = and_(condition, DictUsername.value.like('%' + value + '%'))

    if per_page == 'all':
        for row in db.session.query(DictUsername).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(DictUsername).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(DictUsername).filter(condition).count()
    return response


@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    username_id = request.json.get('id', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    if username_id != '':
        username_id = int(username_id)
        username = db.session.query(DictUsername).filter(DictUsername.id == username_id).first()
        if username:
            username.mark = mark
            username.value = value
            username.update_time = get_time()
            save_sql(username)
            conf.dict_username = db.session.query(DictUsername).all()
            return {'data': {'res': [username_id]}}
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/add', methods=['POST', 'GET'])
@login_check
@fix_response
def add():
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    update_time = get_time()
    username = DictUsername(value=value, mark=mark, update_time=update_time)
    save_sql(username)
    conf.dict_username = db.session.query(DictUsername).all()
    return {'data': {'res': [value]}}


@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    username_id = request.json.get('id', '')
    username_ids = request.json.get('ids', '')
    if username_id != '' or username_ids != '':
        if username_id != '':
            username = db.session.query(DictUsername).filter(DictUsername.id == username_id).first()
            if username:
                db.session.delete(username)
                db.session.commit()
                response['data']['res'].append(username_id)
        elif username_ids != '':
            try:
                for username_id in username_ids.split(','):
                    username_id = username_id.replace(' ', '')
                    username = db.session.query(DictUsername).filter(DictUsername.id == username_id).first()
                    if username:
                        db.session.delete(username)
                        db.session.commit()
                        response['data']['res'].append(username_id)
            except:
                pass
        conf.dict_username = db.session.query(DictUsername).all()
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
