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
from lib.core.model import ScanWhite
from lib.core.enums import ApiStatus
from lib.core.enums import ScanMatchType
from lib.core.enums import ScanMatchPosition
from lib.util.util import get_time
from lib.hander.basehander import save_sql
from lib.core.g import conf
from lib.hander.basehander import fix_response
from lib.hander.basehander import login_check

mod = Blueprint('white', __name__, url_prefix=f"{PREFIX_URL}/manger/white")

@mod.route('/index', methods=['POST', 'GET'])
@login_check
def index():
    ctx = {}
    ctx['title'] = 'White'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    ctx['match_type'] = ScanMatchType
    ctx['match_position'] = ScanMatchPosition
    return render_template('manager/setting/white.html', **ctx)

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
    if match_position != '' and match_position in [ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH,
                                                   ScanMatchPosition.STATUS, ScanMatchPosition.METHOD,
                                                   ScanMatchPosition.RESPONSE_HEADERS, ScanMatchPosition.RESPONSE_BODY]:
        condition = and_(condition, ScanWhite.match_position == match_position)

    if value != '':
        condition = and_(condition, ScanWhite.value.like('%' + value + '%'))

    if match_type != '' and match_type in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        condition = and_(condition, ScanWhite.match_type == match_type )

    if per_page == 'all':
        for row in db.session.query(ScanWhite).filter(condition).all():
            response['data']['res'].append(row.to_json())
    else:
        for row in db.session.query(ScanWhite).filter(condition).paginate(page=page, per_page=per_page).items:
            response['data']['res'].append(row.to_json())
    response['data']['total'] = db.session.query(ScanWhite).filter(condition).count()
    return response


@mod.route('/edit', methods=['POST', 'GET'])
@login_check
@fix_response
def edit():
    white_id = request.json.get('id', '')
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    match_type = request.json.get('match_type', '')
    if match_position not in [ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.STATUS,
                              ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS, ScanMatchPosition.RESPONSE_BODY]:
        return ApiStatus.ERROR_INVALID_INPUT

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    if match_type not in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        return ApiStatus.ERROR_INVALID_INPUT

    if white_id != '':
        white_id = int(white_id)
        white = db.session.query(ScanWhite).filter(ScanWhite.id == white_id).first()
        if white:
            white.mark = mark
            white.match_type = match_type
            white.value = value
            white.match_position = match_position
            white.update_time = get_time()
            save_sql(white)
            conf.scan_white = db.session.query(ScanWhite).all()
            return {'data': {'res': [white_id]}}
    return ApiStatus.ERROR_IS_NOT_EXIST


@mod.route('/add', methods=['POST', 'GET'])
@login_check
@fix_response
def add():
    match_position = request.json.get('match_position', '')
    value = request.json.get('value', '')
    mark = request.json.get('mark', '')
    match_type = request.json.get('match_type', '')

    if match_position not in [ScanMatchPosition.HOST, ScanMatchPosition.URL, ScanMatchPosition.PATH, ScanMatchPosition.STATUS,
                              ScanMatchPosition.METHOD, ScanMatchPosition.RESPONSE_HEADERS, ScanMatchPosition.RESPONSE_BODY]:
        return ApiStatus.ERROR_INVALID_INPUT

    if value == '':
        return ApiStatus.ERROR_INVALID_INPUT

    if match_type not in [ScanMatchType.EQUAL, ScanMatchType.IN, ScanMatchType.REGEX]:
        return ApiStatus.ERROR_INVALID_INPUT

    update_time = get_time()
    white = ScanWhite(match_position=match_position, value=value, match_type=match_type, mark=mark, update_time=update_time)
    save_sql(white)
    conf.scan_white = db.session.query(ScanWhite).all()
    return {'data': {'res': [value]}}

@mod.route('/delete', methods=['POST', 'GET'])
@login_check
@fix_response
def delete():
    response = {'data': {'res': []}}
    white_id = request.json.get('id', '')
    white_ids = request.json.get('ids', '')
    if white_id != '' or white_ids != '':
        if white_id != '':
            white = db.session.query(ScanWhite).filter(ScanWhite.id == white_id).first()
            if white:
                db.session.delete(white)
                db.session.commit()
                response['data']['res'].append(white_id)
        elif white_ids != '':
            try:
                for white_id in white_ids.split(','):
                    white_id = white_id.replace(' ', '')
                    white = db.session.query(ScanWhite).filter(ScanWhite.id == white_id).first()
                    if white:
                        db.session.delete(white)
                        db.session.commit()
                        response['data']['res'].append(white_id)
            except:
                pass
        conf.scan_white = db.session.query(ScanWhite).all()
        return response
    return ApiStatus.ERROR_IS_NOT_EXIST
