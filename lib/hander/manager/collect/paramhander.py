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
from lib.core.model import CollectParam
from lib.core.enums import ApiStatus
from lib.util.util import get_time
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('param', __name__, url_prefix=f"{PREFIX_URL}/manger/param")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Param'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/collect/param.html', **ctx)

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
    param = request.json.get('param', '')
    host = request.json.get('host', '')
    port = request.json.get('port', '')
    condition = (1 == 1)
    if param != '':
        condition = and_(condition, CollectParam.param.like('%' + param + '%'))

    if host != '':
        condition = and_(condition, CollectParam.host.like('%' + host + '%'))

    if port != '':
        condition = and_(condition, CollectParam.port.like('%' + port + '%'))

    if per_page == 'all':
        for row in db.session.query(CollectParam).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(CollectParam).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(CollectParam).filter(condition).count()
    return response

@mod.route('/export', methods=['POST', 'GET'])
@login_check
def export():
    param = request.json.get('param', '')
    host = request.json.get('host', '')
    port = request.json.get('port', '')
    condition = (1 == 1)
    if param != '':
        condition = and_(condition, CollectParam.param.like('%' + param + '%'))

    if host != '':
        condition = and_(condition, CollectParam.host.like('%' + host + '%'))

    if port != '':
        condition = and_(condition, CollectParam.port.like('%' + port + '%'))

    rows = db.session.query(CollectParam).with_entities(CollectParam.param, func.count(CollectParam.param)).filter(condition).group_by(CollectParam.param).order_by(func.count(CollectParam.param).desc()).all()
    content = '\r\n'.join([row[0] for row in rows if row[0] != None])

    filename = 'param_{time}.txt'.format(time=get_time()).replace(':', '-').replace(' ', '_')
    response = make_response(content)
    response.headers['Content-Disposition'] = "attachment; filename={}".format(filename)
    response.headers["Cache-Control"] = "no_store"
    return response


@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    param_id = request.json.get('id', '')
    param_ids = request.json.get('ids', '')
    if param_id != '' or param_ids != '':
        if param_id != '':
            param = db.session.query(CollectParam).filter(CollectParam.id == param_id).first()
            if param:
                db.session.delete(param)
                db.session.commit()
                response['data']['res'].append(param_id)
        elif param_ids != '':
            try:
                for param_id in param_ids.split(','):
                    param_id = param_id.replace(' ', '')
                    param = db.session.query(CollectParam).filter(CollectParam.id == param_id).first()
                    if param:
                        db.session.delete(param)
                        db.session.commit()
                        response['data']['res'].append(param_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
