#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from flask import request
from flask import jsonify
from flask import Blueprint
from flask import url_for
from flask import session
from flask import redirect
from functools import wraps
from lib.hander import app
from lib.hander import db
from lib.core.g import manager_log
from lib.core.model import User
from lib.core.model import Log
from lib.core.model import Engine
from lib.core.enums import ApiStatus
from lib.core.enums import WebLogType
from lib.core.enums import UserRole
from lib.core.enums import UserStatus
from lib.util.util import get_time

mod = Blueprint('base', __name__, url_prefix=f"{PREFIX_URL}/")


@app.errorhandler(400)
def error_400(error):
    if "Failed to decode JSON object" in str(error):
        return jsonify(ApiStatus.ERROR_ILLEGAL_PROTOCOL), 400
    return jsonify(ApiStatus.ERROR_400), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify(ApiStatus.ERROR_404), 404


@app.errorhandler(403)
def not_found(error):
    return jsonify(ApiStatus.ERROR_403), 403


@app.errorhandler(500)
def error_500(error):
    return jsonify(ApiStatus.ERROR_500), 500


@app.after_request
def after_request(resp):
    resp.headers.set("Server", VERSION_STRING)
    resp.headers.set("X-XSS-Protection", "1; mode=block")
    resp.headers.set("X-Frame-Options", "DENY")
    resp.headers.set("X-Content-Type-Options", "nosniff")

    ip = request.remote_addr
    ua = request.user_agent.string
    url = request.url
    method = request.method
    status_code = resp.status_code
    content_length = resp.headers.get('Content-Length', 0)
    referrer = str(request.referrer) if str(request.referrer) != "None" else "-"
    protocol = request.environ.get('SERVER_PROTOCOL')
    x_forwarded_for = request.headers.get('X-Forwarded-For', '"-"')
    manager_log.info(f'{ip} "{method} {url} {protocol}" {status_code} {content_length} "{referrer}" "{ua}" {x_forwarded_for}')

    return resp


def fix_response(func):
    """统一返回的json，补充有status以及msg字段"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        status = ApiStatus.SUCCESS['status']
        msg = ApiStatus.SUCCESS['msg']
        if isinstance(ret, dict):
            if 'status' in ret.keys() and ret['status'] != status:
                status = ret['status']
            if 'msg' in ret.keys() and ret['msg'] != msg:
                msg = ret['msg']
            ret['status'] = status
            ret['msg'] = msg
            return jsonify(ret)
        else:
            pass
    return wrapper


def login_check(func):
    """权限简单校验，防止未授权"""

    @wraps(func)
    def wrapper(*args, **kwargs):

        # 初始化
        user = engine = None
        log_type = WebLogType.WEB

        # api 访问
        if request.path.startswith(f"{PREFIX_URL}/api/"):
            api_key = request.headers.get('API-Key', '')

            # 只收json格式
            if request.json is None:
                return jsonify(ApiStatus.ERROR_ILLEGAL_PROTOCOL)

            # api 访问使用api-key
            elif api_key is None or api_key == '':
                return jsonify(ApiStatus.ERROR_INVALID_API_KEY)

            else:
                # 与api通信，使用api_key
                user = db.session.query(User).filter(User.api_key == api_key).first()
                if user is None:

                    # engine内部通信，使用id
                    engine = db.session.query(Engine).filter(Engine.id == api_key).first()
                    if engine:
                        log_type = WebLogType.OTHER
                    else:
                        return jsonify(ApiStatus.ERROR_INVALID_API_KEY)
                else:
                    log_type = WebLogType.API
        else:
            # Web访问
            user_token = session.get('user')
            if user_token is not None:
                user = User.verify_auth_token(user_token)
                log_type = WebLogType.WEB

        # 用户/接口访问
        if user:
            user_dict = user.to_json()
            if user_dict['status'] != UserStatus.OK:
                return jsonify(ApiStatus.ERROR_ACCOUNT)
            elif user_dict['role'] != UserRole.ADMIN and request.path.startswith(f"{PREFIX_URL}/manager/"):
                return jsonify(ApiStatus.ERROR_ACCESS)
            elif user_dict['role'] == UserRole.ANONYMOUS:
                return jsonify(ApiStatus.ERROR_ACCESS)

            description = str(request.get_json(silent=True))
            log = Log(ip=request.remote_addr, log_type=log_type, description=description, url=request.path, user=user, update_time=get_time())
            save_sql(log)

        # engine内部通信
        elif engine:
            engine.update_time = get_time()
            save_sql(engine)

        # 未认证
        else:
            return redirect(url_for('index.login'))

        return func(*args, **kwargs)
    return wrapper


def save_sql(item):
    """保存数据库"""

    db.session.add(item)
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        if 'PRIMARY' in str(e):
            return True
        manager_log.error(f"Insert error: {str(e)}")
    return False