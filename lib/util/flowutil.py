#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from typing import Type
from typing import Dict
from typing import Union
from typing import Any
from typing import cast
from mitmproxy import exceptions
from mitmproxy.io import compat
from mitmproxy.io import tnetstring
from mitmproxy.flow import Flow
from mitmproxy.tcp import TCPFlow
from mitmproxy.http import HTTPFlow


FLOW_TYPES: Dict[str, Type[Flow]] = dict(
    http=HTTPFlow,
    tcp=TCPFlow,
)


def flow_dumps(flow: Flow):
    """序列化flow数据"""

    d = flow.get_state()
    w = tnetstring.dumps(d)
    return w


def flow_loads(data: bytes):
    """反序列化flow数据"""

    try:
        loaded = cast(
            Dict[Union[bytes, str], Any],
            tnetstring.loads(data),
        )
        try:
            mdata = compat.migrate_flow(loaded)
        except ValueError as e:
            raise exceptions.FlowReadException(str(e))
        if mdata["type"] not in FLOW_TYPES:
            raise exceptions.FlowReadException("Unknown flow type: {}".format(mdata["type"]))
        return FLOW_TYPES[mdata["type"]].from_state(mdata)
    except (ValueError, TypeError) as e:
        if str(e) == "not a tnetstring: empty file":
            return
        raise exceptions.FlowReadException("Invalid data format.")

