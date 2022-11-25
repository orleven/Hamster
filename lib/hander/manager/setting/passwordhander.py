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
from lib.core.model import DictPassword
from lib.core.enums import ApiStatus
from lib.util.util import get_time
from lib.core.g import conf
from lib.hander.basehander import save_sql
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('password', __name__, url_prefix=f"{PREFIX_URL}/manger/password")


@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Username'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/setting/password.html', **ctx)


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
        condition = and_(condition, DictPassword.value.like('%' + value + '%'))

    if per_page == 'all':
        for row in db.session.query(DictPassword).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(DictPassword).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(DictPassword).filter(condition).count()
    return response


@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    password_id = request.json.get('id', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    if password_id != '':
        password_id = int(password_id)
        password = db.session.query(DictPassword).filter(DictPassword.id == password_id).first()
        if password:
            password.mark = mark
            password.value = value
            password.update_time = get_time()
            save_sql(password)
            conf.dict_password = db.session.query(DictPassword).all()
            return {'data': {'res': [password_id]}}
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
    password = DictPassword(value=value, mark=mark, update_time=update_time)
    save_sql(password)
    conf.dict_password = db.session.query(DictPassword).all()
    return {'data': {'res': [value]}}


@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    password_id = request.json.get('id', '')
    password_ids = request.json.get('ids', '')
    if password_id != '' or password_ids != '':
        if password_id != '':
            password = db.session.query(DictPassword).filter(DictPassword.id == password_id).first()
            if password:
                db.session.delete(password)
                db.session.commit()
                response['data']['res'].append(password_id)
        elif password_ids != '':
            try:
                for password_id in password_ids.split(','):
                    password_id = password_id.replace(' ', '')
                    password = db.session.query(DictPassword).filter(DictPassword.id == password_id).first()
                    if password:
                        db.session.delete(password)
                        db.session.commit()
                        response['data']['res'].append(password_id)
            except:
                pass
        conf.dict_password = db.session.query(DictPassword).all()
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
