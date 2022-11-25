#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import re
from flask import request
from flask import render_template
from flask import redirect
from flask import Blueprint
from flask import session
from flask import url_for
from sqlalchemy import or_
from lib.core.model import User
from lib.core.enums import UserStatus
from lib.core.enums import RegexType
from lib.util.util import get_time
from lib.util.util import random_string
from lib.hander import db
from lib.hander.basehander import login_check
from lib.hander.basehander import save_sql

mod = Blueprint('index', __name__, url_prefix=f"{PREFIX_URL}/")


@mod.route('/', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'index'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return redirect(url_for('index.dashboard'))


@mod.route('/dashboard', methods=['POST', 'GET'])
@login_check
def dashboard() -> str:
    ctx = {}
    ctx['title'] = 'dashboard'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/dashboard.html', **ctx)

@mod.route('/login', methods=['POST', 'GET'])
def login():
    ctx = {'title': 'Login', 'message': ''}
    if request.method == 'POST':
        username = request.values.get('username', '')
        password = request.values.get('password', '')
        if username != '' and password != '':
            user = db.session.query(User).filter(or_(User.username == username, User.email == username)).first()
            if user is not None:
                if user.verify_password(password):
                    if user.to_json()['status'] != UserStatus.OK:
                        ctx['message'] = 'Ban account!'
                    else:
                        # 刷新登陆时间以及登陆失败次数
                        update_time = get_time()
                        user.login_time = update_time
                        user.update_time = update_time
                        user.login_failed = 0
                        save_sql(user)
                        session['role'] = user.role
                        session['username'] = user.username
                        session["user"] = user.generate_auth_token(expiration=3600)
                        return redirect(url_for('index.index'))

                user.fail_time = get_time()
                user.login_failed += user.login_failed
                save_sql(user)

            ctx['message'] = 'Incorrect username or password!'
        else:
            ctx['message'] = 'Miss username or password!'

    return render_template('login.html', **ctx)


@mod.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    return redirect(url_for('index.login'))


@mod.route('/profile', methods=['POST', 'GET'])
@login_check
def profile():
    ctx = {}
    user = db.session.query(User).filter(or_(User.username == session['username'])).first()
    ctx['title'] = 'Profile'
    ctx['role'] = session.get('role')
    if request.method == 'POST':
        username = request.values.get('username')
        email = request.values.get('email')
        description = request.values.get('description')
        if username != '':
            user_temp = db.session.query(User).filter(or_(User.username == username)).all()
            if user_temp != None:
                ctx['message'] = 'Exist Username!'
            user.username = username

        if email != '':
            if not re.match(RegexType.EMAIL, email):
                ctx['message'] = 'Invaild Email!'
            user_temp = db.session.query(User).filter(or_(User.email == email)).all()
            if user_temp != None:
                ctx['message'] = 'Exist Email!'
            user.email = email

        if description != '':
            user.description = description
        user.update_time = get_time()
        save_sql(user)
        ctx['message'] = 'Success!'
        ctx['username'] = user.username
        ctx['email'] = user.email
        ctx['description'] = user.description
    else:
        ctx['username'] = user.username
        ctx['email'] = user.email
        ctx['description'] = user.description
        ctx['message'] = ''
    return render_template('manager/profile.html', **ctx)


@mod.route('/reset', methods=['POST', 'GET'])
@login_check
def reset():
    ctx = {}
    user = db.session.query(User).filter(or_(User.username == session['username'])).first()
    ctx['title'] = 'Reset'
    ctx['role'] = session.get('role')
    if request.method == 'POST':
        password = request.values.get('password')
        new_password = request.values.get('new_password')
        confirm_password = request.values.get('confirm_password')
        if password != '' and new_password != '' and confirm_password != '':
            if new_password == confirm_password:
                if user.verify_password(password):
                    if re.match(RegexType.PASSWORD, new_password):
                        user.password = user.generate_password_hash(new_password)
                        user.update_time = get_time()
                        ctx['message'] = 'Success!'
                    else:
                        ctx['message'] = 'Weakpass!'
                else:
                    ctx['message'] = 'Incorrect password!'
            else:
                ctx['message'] = 'Incorrect new_password or confirm_password!'
        else:
            ctx['message'] = 'Miss password or new_password or confirm_password!'
    else:
        ctx['api_key'] = user.api_key
        ctx['message'] = ''
    return render_template('manager/reset.html', **ctx)

@mod.route('/apikey', methods=['POST', 'GET'])
@login_check
def apikey():
    user = db.session.query(User).filter(or_(User.username == session['username'])).first()
    if user:
        user.api_key = random_string(32)
        user.update_time = get_time()
        save_sql(user)
    return redirect(url_for('index.reset'))