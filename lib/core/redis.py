#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import aioredis


class Redis(object):

    def __init__(self, host="127.0.0.1", port=6379, username=None, password=None, decode_responses=True):
        self.host = host
        self.port = port
        self.username = username
        if isinstance(password, int):
            password = str(password)
        self.password = password
        self.decode_responses = decode_responses
        self.redis_pool = None
        self.redis_pool = aioredis.ConnectionPool.from_url(
            f"redis://{self.host}:{self.port}/",
            password=self.password,
            decode_responses=self.decode_responses,
        )
        self.redis_conn = None

    def get_redis_pool(self):
        return self.redis_pool

    async def connect(self):
        self.redis_conn = aioredis.Redis(connection_pool=self.redis_pool)
        return self.redis_conn

    async def ping(self):
        try:
            await self.redis_conn.ping()
            return True
        except:
            return False
