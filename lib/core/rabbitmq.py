#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import asyncio
import aio_pika
import traceback


class RabbitMQ(object):

    def __init__(self, username, password, host="127.0.0.1", port=5672, name="test", exchange_name=None,
                 routing_key=None, retry_count=3):

        self.username = username
        if isinstance(password, int):
            password = str(password)
        self.password = password
        self.host = host
        self.port = int(port)
        self.pre_name = name
        self.retry_count = retry_count
        self.channel = None
        self.connection = None
        self.exchange = None
        self.exchange_name = exchange_name if exchange_name else f'{self.pre_name}'
        self.queue_dic = {}
        self.default_routing_key = routing_key if routing_key else f'{self.pre_name}_dafault'
        self.url = f"amqp://{username}:{password}@{host}:{port}/"

    async def connect(self):
        if self.connection is None or self.channel is None or self.exchange is None or self.channel.is_closed:
            self.queue_dic = {}
            retry_count = self.retry_count
            while retry_count:
                try:
                    self.connection = await aio_pika.connect(
                        host=self.host, port=self.port,
                        login=self.username, password=self.password
                    )
                    self.channel = await self.connection.channel()
                    self.exchange = await self.channel.declare_exchange(
                        self.exchange_name, aio_pika.ExchangeType.DIRECT, durable=True,
                    )
                    return True
                except Exception:
                    retry_count -= retry_count - 1
                    await asyncio.sleep((5 - retry_count) * 5)
                    return False

        return True

    async def close(self):
        try:
            await self.channel.close()
            await self.connection.close()
        except:
            pass
        finally:
            self.channel = None
            self.connection = None
            self.exchange = None

    async def consumer(self, callback):
        while True:
            if await self.connect():
                try:
                    for routing_key in self.queue_dic.keys():
                        message = await self.queue_dic[routing_key].get(fail=False)
                        if message:
                            await callback(message)
                            await message.ack()
                        else:
                            await asyncio.sleep(0.1)
                except:
                    traceback.print_exc()
                    await self.close()
            await asyncio.sleep(0.1)

    async def bind_routing_key(self, routing_key):
        if await self.connect():
            if routing_key not in self.queue_dic.keys():
                queue = await self.channel.declare_queue(name=routing_key, durable=True)
                await queue.bind(self.exchange, routing_key)
                self.queue_dic[routing_key] = queue

    async def unbind_routing_key(self, routing_key):
        if await self.connect():
            if routing_key in self.queue_dic.keys():
                # await self.queue_dic[routing_key].unbind(self.exchange, routing_key)
                self.queue_dic[routing_key] = None
                del self.queue_dic[routing_key]

    def get_routing_key_list(self):
        return self.queue_dic.keys()

    async def publish(self, message, priority=1, delivery_mode=2, routing_key=None):
        if await self.connect():
            routing_key = routing_key if routing_key else self.default_routing_key
            await self.bind_routing_key(routing_key)
            await self.exchange.publish(
                aio_pika.Message(message, priority=priority, delivery_mode=delivery_mode),
                routing_key=routing_key
            )
