#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import request
from flask import render_template
from flask import Blueprint
from flask import session
from sqlalchemy import and_
from lib.hander import db
from lib.util.util import get_time
from lib.util.util import get_timestamp
from lib.core.g import conf
from lib.core.env import *
from lib.core.model import Engine
from lib.core.enums import EngineStatus
from lib.core.enums import ApiStatus
from lib.hander.basehander import save_sql
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('engine', __name__, url_prefix=f"{PREFIX_URL}/manger/engine")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Engine'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['engine_status'] = EngineStatus
    return render_template('manager/system/engine.html', **ctx)

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
    name = request.json.get('name', '')
    status = request.json.get('status', '')
    ip = request.json.get('ip', '')
    condition = (1 == 1)
    if name != '':
        condition = and_(condition, Engine.name.like('%' + name + '%'))

    if status != '':
        condition = and_(condition, Engine.status.like('%' + status + '%'))

    if ip != '':
        condition = and_(condition, Engine.ip.like('%' + ip + '%'))

    if per_page == 'all':
        engines = db.session.query(Engine).filter(condition).order_by(Engine.update_time.desc()).all()
    else:
        engines = db.session.query(Engine).filter(condition).order_by(Engine.update_time.desc()).paginate(page=page,
                                                                                                          per_page=per_page).items
    for row in engines:
        # 刷新状态
        laster = row.update_time
        temp = get_time(get_timestamp() - conf.basic.heartbeat_time - 300)
        if temp > laster:
            if row.status == EngineStatus.OK:
                row.status = EngineStatus.OFFLINE
            row.task_num = 0
            save_sql(row)
        response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(Engine).filter(condition).count()
    return response

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    engine_id = request.json.get('id', '')
    engine_ids = request.json.get('ids', '')
    if engine_id != '' or engine_ids != '':
        if engine_id != '':
            engine = db.session.query(Engine).filter(Engine.id == engine_id).first()
            if engine:
                db.session.delete(engine)
                db.session.commit()
                response['data']['res'].append(engine_id)
        if engine_ids != '':
            try:
                for engine_id in engine_ids.split(','):
                    engine_id = engine_id.replace(' ', '')
                    engine = db.session.query(Engine).filter(Engine.id == engine_id).first()
                    if engine:
                        db.session.delete(engine)
                        db.session.commit()
                        response['data']['res'].append(engine_id)
            except:
                pass
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    engine_id = request.json.get('id', '')
    name = request.json.get('name', '')
    description = request.json.get('description', '')
    scan_max_task_num = request.json.get('scan_max_task_num', '')
    status = request.json.get('status', '')
    mark = request.json.get('mark', '')

    if status not in [EngineStatus.OK, EngineStatus.STOP]:
        return ApiStatus.ERROR_INVALID_INPUT

    if engine_id != '':
        engine_id = engine_id
        engine = db.session.query(Engine).filter(Engine.id == engine_id).first()
        if engine:
            engine.mark = mark
            engine.name = name
            engine.description = description
            engine.scan_max_task_num = scan_max_task_num
            engine.status = status
            engine.update_time = get_time()
            save_sql(engine)
            return {'data': {'res': [engine_id]}}

    return ApiStatus.ERROR_IS_NOT_EXIST
