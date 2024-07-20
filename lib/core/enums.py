#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

class ScanMode:
    CACHE = "cache"
    NOCACHE = "nocache"

class CustomLogging:
    """日志等级"""

    SUCCESS = 9
    ERROR = 8
    WARNING = 7
    INFO = 6
    DEBUG = 5
    CRITICAL = 10


class WebLogType:
    """Web日志类型"""

    WEB = "Web"
    API = "Api"
    OTHER = "Other"


class UserRole:
    """用户角色类型"""

    ADMIN = "Admin"
    USER = "User"
    ANONYMOUS = "Anonymous"


class UserStatus:
    """用户状态"""

    OK = "OK"
    BAN = "Ban"


class AddonEnable:
    """插件可用"""

    ENABLE = True
    DISABLE = False


class ScanMatchPosition:
    """扫描黑白名单配置位置"""

    HOST = "Host"
    URL = "Url"
    PATH = "Path"
    QUERY = "Query"
    STATUS = "Status"
    METHOD = "Method"
    # REQUEST_HEADERS = "RequestHeaders"
    # REQUEST_COOKIES = "RequestCookies"
    # REQUEST_BODY = "RequestBody"
    RESPONSE_HEADERS = "ResponseHeaders"
    RESPONSE_BODY = "ResponseBody"


class ScanMatchType:
    """扫描黑白名单配置类型"""

    REGEX = "Regex"
    IN = "In"
    EQUAL = "Equal"


class AddonType:
    """脚本扫描类型"""

    # 域名调用一次
    HOST_ONCE = "HostOnce"

    # 所有层级目录都调用
    DIR_ALL = "DirAll"

    # 当前文件调用
    FILE_ONCE = "FileOnce"

    # URL调用
    URL_ONCE = "URLOnce"

    # Websocket
    WEBSOCKET_ONCE = "WSOnce"

    # 不调用
    NONE = None

class EngineType:
    """
    引擎类型
    """

    BASE_AGENT = "BaseAgent"
    VUL_AGENT = "VulAgent"

    BASE_MASTER = "BaseMaster"
    SUPPORT_MASTER = "SupportMaster"
    SERVER_MASTER = "ServerMaster"
    SIMPLE_MASTER = "SimpleMaster"

    BASE_MANAGER = "BaseManager"
    WEB_MANAGER = "WebManager"

class EngineStatus:
    """引擎状态"""

    OK = "OK"
    STOP = "STOP"
    OFFLINE = "Offline"
    UNKNOWN = "Unknown"


class ParameterType:
    """参数数据类型"""

    JSON = "Json"
    DICT = "Dict"
    FORMDATA = "Formdata"
    PARAMETER = "Parameter"
    FILE = "File"
    OTHER = "Other"
    INT = "Int"
    STRING = "String"
    BOOLEAN = "Boolean"
    BYTES = "Bytes"
    LIST = "List"
    FLOAT = "Float"


class WebsocketType:
    """Websocket类型"""

    BINARY = "Binary"
    TEXT = "Text"

class FlowType:
    """Flow类型"""

    WEB = "Web"
    WEBSOCKET = "Websocket"


class EncodeType:
    """常见编码方式"""

    URL_ENCODE = "Urlencode"
    BASE64_ENCODE = "Base64encode"


class VulLevel:
    """漏洞等级"""
    INFO = "Info"
    LOWER = "Lower"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    NONE = None


class VulType:
    """漏洞类型"""

    SSRF = "SSRF"
    SQL_Inject = "SqlInject"
    XSS = "XSS"
    INFO = "Info"
    CORS = "CORS"
    JSONP = "JSONP"
    RCE = "RCE"
    XXE = "XEE"
    DOS = "Dos"
    SENSITIVE_INFO = "SensitiveInfomation"
    BYPASS_AUTHORITY = "BypassAuthority"
    UNAUTHORIZED_ACCESS = "UnauthorizedAccess"
    INFO_FILE = "Information File"
    WEAKPASS = "WeakPass"
    OTHER = "Other"
    NONE = None
    REDIRECT = "Redirect"
    FILE_INCLUDE = "File Include"
    FILE_DOWNLOAD = "File Download"
    FILE_UPLOAD = "File Upload"


class ApiStatus:
    """后端API接口返回码"""

    INIT = {"status": 0, "msg": "", "data": {}}
    SUCCESS = {"status": 10000, "msg": "Success!", "data": {}}

    ERROR = {"status": 20000, "msg": "Error!", "data": {}}
    ERROR_INVALID_INPUT = {"status": 20001, "msg": "Invalid input!", "data": {}}
    ERROR_INVALID_INPUT_ADDON_NAME = {"status": 20001, "msg": "Invalid addon name!", "data": {}}
    ERROR_INVALID_INPUT_EMAIL = {"status": 20001, "msg": "Invalid email!", "data": {}}
    ERROR_INVALID_INPUT_USERNAME = {"status": 20001, "msg": "Invalid username!", "data": {}}
    ERROR_INVALID_INPUT_FILE = {"status": 20001, "msg": "Invalid file!", "data": {}}
    ERROR_INVALID_INPUT_PASSWORD = {"status": 20001, "msg": "Invalid password!", "data": {}}
    ERROR_INVALID_INPUT_MOBILE = {"status": 20001, "msg": "Invalid mobile!", "data": {}}
    ERROR_INVALID_TOKEN = {"status": 20002, "msg": "Invalid token!", "data": {}}

    ERROR_System = {"status": 30000, "msg": "System error!", "data": {}}
    ERROR_IS_NOT_EXIST = {"status": 30001, "msg": "Data is not exist!", "data": {}}
    ERROR_PRIMARY = {"status": 30002, "msg": "Data existed!", "data": {}}
    ERROR_LOGIN = {"status": 30003, "msg": "Incorrect username or password!", "data": {}}  # 登陆失败
    ERROR_ACCOUNT = {"status": 30004, "msg": "Abnormal account!", "data": {}}  # 账户异常
    ERROR_INVALID_API_KEY = {"status": 30005, "msg": "Invalid api-key!", "data": {}}
    ERROR_ACCESS = {"status": 30006, "msg": "Invalid access!", "data": {}}  # 非法访问

    ERROR_400 = {"status": 40000, "msg": "Bad Request!", "data": {}}
    ERROR_ILLEGAL_PROTOCOL = {"status": 40001, "msg": "Illegal protocol!", "data": {}}  # 解析失败
    ERROR_MISSING_PARAMETER = {"status": 40002, "msg": "Missing parameter!", "data": {}}  # 缺乏参数
    ERROR_403 = {"status": 40003, "msg": "Forbidden!", "data": {}}
    ERROR_404 = {"status": 40004, "msg": "Not Found!", "data": {}}
    ERROR_500 = {"status": 40005, "msg": "500 Error!", "data": {}}
    ERROR_API_OFFLINE = {"status": 40006, "msg": "Api offline!", "data": {}}

    UNKNOWN = {"status": 99999, "msg": "Unknown error! Please contact the administrator!", "data": {}}


class RegexType:
    """正则类型"""

    IPv4 = r"^((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}$"
    IPv6 = r"^(?:(?:[0-9a-fA-F]{1,4}:){7}(?:[0-9a-fA-F]{1,4}|:)|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,5}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,6}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)||:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$"
    DOMAIN = r"^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
    URL = r"^[a-z]{3,6}://(?:(?:[\w_-]+(?:(?:\.[\w_-]+)+))|(?:\[[0-9a-zA-z:]+\]))(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?$"
    MD5 = r"^[a-fA-F0-9]{32}$"
    SHA1 = r"^[a-fA-F0-9]{40}$"
    SHA256 = r"^[a-fA-F0-9]{64}$"
    EMAIL = r"^([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+)$"
    TIME = r"^\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:\d{2}$"
    MOBILE = r"^[0-9\-]{3,15}$"
    PASSWORD = r"^(?![0-9]+$)(?![a-z]+$)(?![A-Z]+$)(?!([^(0-9a-zA-Z)])+$).{6,20}$"
    ONEDAYTIME = r"^(20|21|22|23|[0-1]\d):[0-5]\d:[0-5]\d$"
