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
from lib.core.env import *
from lib.core.model import ScanTime
from lib.core.enums import ApiStatus
from lib.core.enums import ScanMatchType
from lib.core.enums import RegexType
from lib.core.enums import ScanMatchPosition
from lib.util.util import get_time
from lib.hander.basehander import save_sql
from lib.core.g import conf
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('time', __name__, url_prefix=f"{PREFIX_URL}/manger/time")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Time'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['match_type'] = ScanMatchType
    ctx['match_position'] = ScanMatchPosition
    return render_template('manager/setting/time.html', **ctx)

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
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    match_type = request.json.get('match_type', '')
    condition = (1 == 1)
    if match_position != '' and match_position in [
        ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.QUERY,
        ScanMatchPosition.STATUS, ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS,
        ScanMatchPosition.RESPONSE_BODY
    ]:
        condition = and_(condition, ScanTime.match_position == match_position)

    if value != '':
        condition = and_(condition, ScanTime.value.like('% ' + value + '%'))

    if match_type != '' and match_type in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        condition = and_(condition, ScanTime.match_type == match_type )

    if per_page == 'all':
        for row in db.session.query(ScanTime).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(ScanTime).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(ScanTime).filter(condition).count()
    return response


@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    time_id = request.json.get('id', '')
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    match_type = request.json.get('match_type', '')
    start_time = request.json.get('start_time', '')
    end_time = request.json.get('end_time', '')

    if match_position not in [
        ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.QUERY,
        ScanMatchPosition.STATUS, ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS,
        ScanMatchPosition.RESPONSE_BODY
    ]:
        return ApiStatus.ERROR_INVALID_INPUT

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    if start_time == '' or not re.match(RegexType.ONEDAYTIME, start_time):
        return ApiStatus.ERROR_INVALID_INPUT

    if end_time == '' or not re.match(RegexType.ONEDAYTIME, end_time):
        return ApiStatus.ERROR_INVALID_INPUT

    if match_type not in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        return ApiStatus.ERROR_INVALID_INPUT

    if time_id != '':
        time_id = int(time_id)
        time = db.session.query(ScanTime).filter(ScanTime.id == time_id).first()
        if time:
            time.mark = mark
            time.match_type = match_type
            time.value = value
            time.match_position = match_position
            time.start_time = start_time
            time.end_time = end_time
            time.update_time = get_time()
            save_sql(time)
            conf.scan_time = db.session.query(ScanTime).all()
            return {'data': {'res': [time_id]}}
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/add', methods=['POST', 'GET'])
@login_check
@fix_response
def add():
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    match_type = request.json.get('match_type', '')
    start_time = request.json.get('start_time', '')
    end_time = request.json.get('end_time', '')

    if match_position not in [
        ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.QUERY,
        ScanMatchPosition.STATUS, ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS,
        ScanMatchPosition.RESPONSE_BODY
    ]:
        return ApiStatus.ERROR_INVALID_INPUT

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    if start_time == '' or not re.match(RegexType.ONEDAYTIME, start_time):
        return ApiStatus.ERROR_INVALID_INPUT

    if end_time == '' or not re.match(RegexType.ONEDAYTIME, end_time):
        return ApiStatus.ERROR_INVALID_INPUT

    if match_type not in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        return ApiStatus.ERROR_INVALID_INPUT

    update_time = get_time()
    time = ScanTime(match_position=match_position, value=value, match_type=match_type, mark=mark, end_time=end_time, start_time=start_time, update_time=update_time)
    save_sql(time)
    conf.scan_time = db.session.query(ScanTime).all()
    return {'data': {'res': [value]}}

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    time_id = request.json.get('id', '')
    time_ids = request.json.get('ids', '')
    if time_id != '' or time_ids != '':
        if time_id != '':
            time = db.session.query(ScanTime).filter(ScanTime.id == time_id).first()
            if time:
                db.session.delete(time)
                db.session.commit()
                response['data']['res'].append(time_id)
        elif time_ids != '':
            try:
                for time_id in time_ids.split(','):
                    time_id = time_id.replace(' ', '')
                    time = db.session.query(ScanTime).filter(ScanTime.id == time_id).first()
                    if time:
                        db.session.delete(time)
                        db.session.commit()
                        response['data']['res'].append(time_id)
            except:
                pass
        conf.scan_time = db.session.query(ScanTime).all()
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
