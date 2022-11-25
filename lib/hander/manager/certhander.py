#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from flask import render_template
from flask import Blueprint
from flask import session
from mitmproxy.options import CONF_BASENAME
from mitmproxy.options import CONF_DIR
from lib.core.env import *

mod = Blueprint('cert', __name__, url_prefix=f"{PREFIX_URL}/cert")

@mod.route('/index')
def index():
    ctx = {}
    ctx['title'] = 'Cert'
    ctx['role'] = session.get('role')
    ctx['username'] = session.get('username')
    return render_template('manager/cert.html', **ctx)


@mod.route('/pem')
def pem():
    return read_cert("pem", "application/x-x509-ca-cert")


@mod.route('/p12')
def p12():
    return read_cert("p12", "application/x-pkcs12")


@mod.route('/cer')
def cer():
    return read_cert("cer", "application/x-x509-ca-cert")


def read_cert(ext, content_type):
    filename = CONF_BASENAME + f"-ca-cert.{ext}"
    p = os.path.join(CONF_DIR, filename)
    p = os.path.expanduser(p)
    with open(p, "rb") as f:
        cert = f.read()

    return cert, {
        "Content-Type": content_type,
        "Content-Disposition": f"inline; filename={filename}",
    }
