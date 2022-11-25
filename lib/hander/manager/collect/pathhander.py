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
from lib.core.model import CollectPath
from lib.core.enums import ApiStatus
from lib.util.util import get_time
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('path', __name__, url_prefix=f"{PREFIX_URL}/manger/path")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Path'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/collect/path.html', **ctx)

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
    file = request.json.get('file', '')
    dir = request.json.get('dir', '')
    port = request.json.get('port', '')
    host = request.json.get('host', '')
    path = request.json.get('path', '')
    condition = (1 == 1)
    if host != '':
        condition = and_(condition, CollectPath.host.like('%' + host + '%'))

    if port != '':
        condition = and_(condition, CollectPath.port.like('%' + port + '%'))

    if path != '':
        condition = and_(condition, CollectPath.path.like('%' + path + '%'))

    if file != '':
        condition = and_(condition, CollectPath.file.like('%' + file + '%'))

    if dir != '':
        condition = and_(condition, CollectPath.dir.like('%' + dir + '%'))

    if per_page == 'all':
        for row in db.session.query(CollectPath).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(CollectPath).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(CollectPath).filter(condition).count()
    return response

@mod.route('/export', methods=['POST', 'GET'])
@login_check
def export():
    file = request.json.get('file', '')
    dir = request.json.get('dir', '')
    port = request.json.get('port', '')
    host = request.json.get('host', '')
    path = request.json.get('path', '')
    condition = (1 == 1)
    if host != '':
        condition = and_(condition, CollectPath.host.like('%' + host + '%'))

    if port != '':
        condition = and_(condition, CollectPath.port.like('%' + port + '%'))

    if path != '':
        condition = and_(condition, CollectPath.path.like('%' + path + '%'))

    if file != '':
        condition = and_(condition, CollectPath.file.like('%' + file + '%'))

    if dir != '':
        condition = and_(condition, CollectPath.dir.like('%' + dir + '%'))

    rows = db.session.query(CollectPath).with_entities(CollectPath.file, func.count(CollectPath.file)).filter(condition).group_by(CollectPath.file).order_by(func.count(CollectPath.file).desc()).all()
    content = '\r\n'.join([row[0] for row in rows if row[0] != None])
    filename = 'path_{time}.txt'.format(time=get_time()).replace(':', '-').replace(' ', '_')
    response = make_response(content)
    response.headers['Content-Disposition'] = "attachment; filename={}".format(filename)
    response.headers["Cache-Control"] = "no_store"
    return response

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    path_id = request.json.get('id', '')
    path_ids = request.json.get('ids', '')
    if path_id != '' or path_ids != '':
        if path_id != '':
            path = db.session.query(CollectPath).filter(CollectPath.id == path_id).first()
            if path:
                db.session.delete(path)
                db.session.commit()
                response['data']['res'].append(path_id)
        elif path_ids != '':
            try:
                for path_id in path_ids.split(','):
                    path_id = path_id.replace(' ', '')
                    path = db.session.query(CollectPath).filter(CollectPath.id == path_id).first()
                    if path:
                        db.session.delete(path)
                        db.session.commit()
                        response['data']['res'].append(path_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST

