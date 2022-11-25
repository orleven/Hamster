#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from lib.core.g import conf
from lib.core.g import mysql

app = Flask(PROJECT_NAME, template_folder=TEMPLATE_PATH, static_folder=STATIC_PATH, static_url_path=f"{PREFIX_URL}/{STATIC}")
app.config["DEBUG"] = conf.basic.debug
app.config['SECRET_KEY'] = conf.basic.secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = mysql.get_sync_sqlalchemy_database_url()
app.config['SQLALCHEMY_ECHO'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 100
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 20
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db = SQLAlchemy(app)


from lib.hander import basehander
app.register_blueprint(basehander.mod)

from lib.hander import indexhander
app.register_blueprint(indexhander.mod)

from lib.hander.manager import certhander
app.register_blueprint(certhander.mod)

from lib.hander.manager import vulhander
app.register_blueprint(vulhander.mod)

from lib.hander.manager.cache import packethander
app.register_blueprint(packethander.mod)

from lib.hander.manager.cache import cachehander
app.register_blueprint(cachehander.mod)

from lib.hander.manager.cache import dnsloghander
app.register_blueprint(dnsloghander.mod)

from lib.hander.manager.collect import pathhander
app.register_blueprint(pathhander.mod)

from lib.hander.manager.collect import paramhander
app.register_blueprint(paramhander.mod)

from lib.hander.manager.collect import emailhander
app.register_blueprint(emailhander.mod)

from lib.hander.manager.collect import corshander
app.register_blueprint(corshander.mod)

from lib.hander.manager.collect import jsonphander
app.register_blueprint(jsonphander.mod)

from lib.hander.manager.setting import usernamehander
app.register_blueprint(usernamehander.mod)

from lib.hander.manager.setting import passwordhander
app.register_blueprint(passwordhander.mod)

from lib.hander.manager.setting import whitehander
app.register_blueprint(whitehander.mod)

from lib.hander.manager.setting import blackhander
app.register_blueprint(blackhander.mod)

from lib.hander.manager.setting import timehander
app.register_blueprint(timehander.mod)

from lib.hander.manager.system import enginehander
app.register_blueprint(enginehander.mod)

from lib.hander.manager.system import addonhander
app.register_blueprint(addonhander.mod)

from lib.hander.manager.system import userhander
app.register_blueprint(userhander.mod)

from lib.hander.manager.system import loghander
app.register_blueprint(loghander.mod)

from lib.hander.api import addonhander
app.register_blueprint(addonhander.mod)