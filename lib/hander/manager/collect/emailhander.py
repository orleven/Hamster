#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from flask import make_response
from sqlalchemy import and_
from sqlalchemy import func
from lib.hander import db
from lib.core.env import *
from lib.core.model import CollectEmail
from lib.core.enums import ApiStatus
from lib.util.util import get_time
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('email', __name__, url_prefix=f"{PREFIX_URL}/manger/email")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Email'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/collect/email.html', **ctx)

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
    path = request.json.get('path', '')
    port = request.json.get('port', '')
    host = request.json.get('host', '')
    email = request.json.get('email', '')
    condition = (1 == 1)
    if host != '':
        condition = and_(condition, CollectEmail.host.like('%' + host + '%'))

    if port != '':
        condition = and_(condition, CollectEmail.port.like('%' + port + '%'))

    if email != '':
        condition = and_(condition, CollectEmail.email.like('%' + email + '%'))

    if path != '':
        condition = and_(condition, CollectEmail.path.like('%' + path + '%'))

    if per_page == 'all':
        for row in db.session.query(CollectEmail).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(CollectEmail).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(CollectEmail).filter(condition).count()
    return response

@mod.route('/export', methods=['POST', 'GET'])
@login_check
def export():
    path = request.json.get('path', '')
    port = request.json.get('port', '')
    host = request.json.get('host', '')
    email = request.json.get('email', '')
    condition = (1 == 1)
    if host != '':
        condition = and_(condition, CollectEmail.host.like('%' + host + '%'))

    if port != '':
        condition = and_(condition, CollectEmail.port.like('%' + port + '%'))

    if email != '':
        condition = and_(condition, CollectEmail.email.like('%' + email + '%'))

    if path != '':
        condition = and_(condition, CollectEmail.path.like('%' + path + '%'))

    rows = db.session.query(CollectEmail).with_entities(CollectEmail.email, func.count(CollectEmail.email)).filter(condition).group_by(CollectEmail.email).order_by(func.count(CollectEmail.email).desc()).all()
    content = '\r\n'.join([row[0] for row in rows if row[0] != None])
    filename = 'email_{time}.txt'.format(time=get_time()).replace(':', '-').replace(' ', '_')
    response = make_response(content)
    response.headers['Content-Disposition'] = "attachment; filename={}".format(filename)
    response.headers["Cache-Control"] = "no_store"
    return response

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    email_id = request.json.get('id', '')
    email_ids = request.json.get('ids', '')
    if email_id != '' or email_ids != '':
        if email_id != '':
            email = db.session.query(CollectEmail).filter(CollectEmail.id == email_id).first()
            if email:
                db.session.delete(email)
                db.session.commit()
                response['data']['res'].append(email_id)
        elif email_ids != '':
            try:
                for email_id in email_ids.split(','):
                    email_id = email_id.replace(' ', '')
                    email = db.session.query(CollectEmail).filter(CollectEmail.id == email_id).first()
                    if email:
                        db.session.delete(email)
                        db.session.commit()
                        response['data']['res'].append(email_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST