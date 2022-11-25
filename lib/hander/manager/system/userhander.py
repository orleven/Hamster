#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from lib.hander import db
from lib.core.g import conf
from lib.core.env import *
from lib.core.model import User
from lib.util.util import get_time
from lib.util.util import random_string
from lib.core.enums import ApiStatus
from lib.core.enums import UserStatus
from lib.core.enums import RegexType
from lib.core.enums import UserRole
from lib.hander.basehander import save_sql
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check


mod = Blueprint('user', __name__, url_prefix=f"{PREFIX_URL}/manger/user")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'User'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['user_status'] = UserStatus
    ctx['user_role'] = UserRole
    return render_template('manager/system/user.html', **ctx)

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
    username = request.json.get('username', '')
    email = request.json.get('email', '')
    role = request.json.get('role', '')
    status = request.json.get('status', '')

    condition = (1 == 1)
    if username != '':
        condition = and_(condition, User.username.like('%' + username + '%'))

    if email != '':
        condition = and_(condition, User.email.like('%' + email + '%'))

    if status != '' and status in [UserStatus.OK, UserStatus.BAN]:
        condition = and_(condition, User.status == status)

    if role != '' and role in [UserRole.ADMIN, UserRole.ANONYMOUS, UserRole.USER]:
        condition = and_(condition, User.role == role)

    if per_page == 'all':
        for row in db.session.query(User).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(User).filter(condition).order_by(User.update_time.desc()).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(User).filter(condition).count()
    return response

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    user_id = request.json.get('id', '')
    user_ids = request.json.get('ids', '')
    if user_id != '' or user_ids != '':
        if user_id != '':
            user_id = int(user_id)
            user = db.session.query(User).filter(User.id == user_id).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                response['data']['res'].append(user_id)
        if user_ids != '':
            try:
                for user_id in user_ids.split(','):
                    user_id = int(user_id.replace(' ', ''))
                    user = db.session.query(User).filter(User.id == user_id).first()
                    if user:
                        db.session.delete(user)
                        db.session.commit()
                        response['data']['res'].append(user_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/add', methods=['POST', 'GET'])
@login_check
@fix_response
def add():
    email = request.json.get('email', '')
    username = request.json.get('username', '')
    mark = request.json.get('mark', '')
    role = request.json.get('role', '')
    description = request.json.get('description', '')

    if not re.match(RegexType.EMAIL, email):
        return ApiStatus.ERROR_INVALID_INPUT_EMAIL

    if db.session.query(User).filter(User.email == email).first():
        return ApiStatus.ERROR_PRIMARY

    if username == None or username == '':
        username = email.split('@')[0]

    if role == '' or role not in [UserRole.ADMIN, UserRole.ANONYMOUS, UserRole.USER]:
        return ApiStatus.ERROR_INVALID_INPUT

    status = UserStatus.OK
    login_failed = 0
    update_time = create_time = get_time()
    api_key = random_string(32)

    user = User(email=email, username=username, status=status, mark=mark, role=role, update_time=update_time, api_key=api_key,
                login_failed=login_failed, create_time=create_time, description=description)
    user.password = user.generate_password_hash(conf.basic.default_password)

    if save_sql(user):
        return {'user': {'res': [email]}}
    else:
        return ApiStatus.ERROR

@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    id = int(request.json.get('id', ''))
    # email = request.json.get('email', '')
    # username = request.json.get('username', '')
    mark = request.json.get('mark', '')
    role = request.json.get('role', '')
    description = request.json.get('description', '')
    status = request.json.get('status', '')
    user = db.session.query(User).filter_by(id=id).first()
    if user:
        # if re.match(RegexType.EMAIL, email):
        #     user.email = email
        #     user.username = email.split('@')[0]
        # else:
        #     return ApiStatus.ERROR_INVALID_INPUT_EMAIL

        # if db.session.query(User).filter(and_(User.email == email, User.id != user.id)).first():
        #     return ApiStatus.ERROR_PRIMARY

        if status in [UserStatus.OK, UserStatus.BAN]:
            user.status = status
        else:
            return ApiStatus.ERROR_INVALID_INPUT

        if role != '' and role in [UserRole.ADMIN, UserRole.ANONYMOUS, UserRole.USER]:
            user.role = role
        else:
            return ApiStatus.ERROR_INVALID_INPUT

        user.update_time = get_time()
        user.mark = mark
        user.description = description
        if save_sql(user):
            return {'user': {'res': [user.id]}}
        else:
            return ApiStatus.ERROR

    return ApiStatus.ERROR_IS_NOT_EXIST

@mod.route('/reset', methods=['POST', 'GET'])
@login_check
@fix_response
def reset():
    id = int(request.json.get('id', ''))
    user = db.session.query(User).filter_by(id=id).first()
    if user:
        user.password = user.generate_password_hash(conf.basic.default_password)
        user.update_time = get_time()
        if save_sql(user):
            return {'user': {'res': [user.id]}}
        else:
            return ApiStatus.ERROR

    return ApiStatus.ERROR_IS_NOT_EXIST
