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
from lib.core.model import VulFilter
from lib.core.enums import ApiStatus
from lib.core.enums import ScanMatchType
from lib.core.enums import ScanMatchPosition
from lib.util.util import get_time
from lib.hander.basehander import save_sql
from lib.core.g import conf
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('filter', __name__, url_prefix=f"{PREFIX_URL}/manger/filter")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'Filter'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['match_type'] = ScanMatchType
    ctx['match_position'] = ScanMatchPosition
    return render_template('manager/setting/filter.html', **ctx)

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
    if match_position != '' and match_position in[
        ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.QUERY,
        ScanMatchPosition.STATUS, ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS,
        ScanMatchPosition.RESPONSE_BODY
    ]:
        condition = and_(condition, VulFilter.match_position == match_position)

    if value != '':
        condition = and_(condition, VulFilter.value.like('%' + value + '%'))

    if match_type != '' and match_type in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        condition = and_(condition, VulFilter.match_type == match_type )

    if per_page == 'all':
        for row in db.session.query(VulFilter).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(VulFilter).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(VulFilter).filter(condition).count()
    return response


@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    filter_id = request.json.get('id', '')
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    match_type = request.json.get('match_type', '')

    if match_position not in [
        ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.QUERY,
        ScanMatchPosition.STATUS, ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS,
        ScanMatchPosition.RESPONSE_BODY
    ]:
        return ApiStatus.ERROR_INVALID_INPUT

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    if match_type not in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        return ApiStatus.ERROR_INVALID_INPUT

    if filter_id != '':
        filter_id = int(filter_id)
        filter = db.session.query(VulFilter).filter(VulFilter.id == filter_id).first()
        if filter:
            filter.mark = mark
            filter.match_type = match_type
            filter.value = value
            filter.match_position = match_position
            filter.update_time = get_time()
            save_sql(filter)
            conf.scan_filter = db.session.query(VulFilter).all()
            return {'data': {'res': [filter_id]}}
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/add', methods=['POST', 'GET'])
@login_check
@fix_response
def add():
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    match_type = request.json.get('match_type', '')

    if match_position not in [
        ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.QUERY,
        ScanMatchPosition.STATUS, ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS,
        ScanMatchPosition.RESPONSE_BODY
    ]:
        return ApiStatus.ERROR_INVALID_INPUT

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    if match_type not in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        return ApiStatus.ERROR_INVALID_INPUT

    update_time = get_time()
    filter = VulFilter(match_position=match_position, value=value, match_type=match_type, mark=mark, update_time=update_time)
    save_sql(filter)
    conf.scan_filter = db.session.query(VulFilter).all()
    return {'data': {'res': [value]}}

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    filter_id = request.json.get('id', '')
    filter_ids = request.json.get('ids', '')
    if filter_id != '' or filter_ids != '':
        if filter_id != '':
            filter = db.session.query(VulFilter).filter(VulFilter.id == filter_id).first()
            if filter:
                db.session.delete(filter)
                db.session.commit()
                response['data']['res'].append(filter_id)
        elif filter_ids != '':
            try:
                for filter_id in filter_ids.split(','):
                    filter_id = filter_id.replace(' ', '')
                    filter = db.session.query(VulFilter).filter(VulFilter.id == filter_id).first()
                    if filter:
                        db.session.delete(filter)
                        db.session.commit()
                        response['data']['res'].append(filter_id)
            except:
                pass
        conf.scan_filter = db.session.query(VulFilter).all()
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
