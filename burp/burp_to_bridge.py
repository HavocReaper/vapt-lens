# -*- coding: utf-8 -*-
"""
VAPT Lens - optional Burp Suite Community -> local bridge feeder (Jython 2.7).

LOAD STEPS (Burp Suite Community):
  1. Extender > Options > Python Environment -> set "Python Environment" to the
     Jython standalone JAR (download jython-standalone-2.7.x.jar). Burp must use
     Jython 2.7 to load Python extensions; the stock JAR is not bundled.
  2. Extender > Extensions > Add -> Extension type: Python -> select this file
     (burp/burp_to_bridge.py) -> Next until loaded.
  3. Confirm "VAPT Lens Bridge Feeder" appears in Extender > Extensions with no
     errors (check the Errors tab in Details if it does not).
  4. Start the bridge first: `npm run bridge` from the project root. It listens
     on http://127.0.0.1:8787 by default.
  5. If your bridge runs elsewhere, edit the BRIDGE_URL constant below, then
     unload/reload the extension.

SAFETY: only request metadata is sent - method, host, path, query/body parameter
NAMES, allowlisted header names, status, content type and length. Request and
response bodies, cookie values, auth headers and ALL parameter values are never
transmitted. The bridge caps the number of stored items, not this extension.
"""

from burp import IBurpExtender, IProxyListener, IParameter
import urllib2
import json
import threading

BRIDGE_URL = "http://127.0.0.1:8787/api/burp/stream"
TIMEOUT_SECONDS = 1.0
MAX_PATH = 300

# Only these header names are ever captured. Cookie, Authorization, Proxy-*
# and Set-Cookie can never be included because they are not on this list.
HEADER_ALLOWLIST = set([
    "content-type",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "server",
    "x-powered-by",
    "cache-control",
])

REDACT_WORDS = ("token", "key", "secret", "auth", "session", "bearer")


def _redact(value):
    """Keep short non-sensitive header values; redact anything secret-looking."""
    if value is None:
        return ""
    text = value.strip()
    lowered = text.lower()
    for word in REDACT_WORDS:
        if word in lowered:
            return "[redacted]"
    return text[:300]


def _safe_path(value):
    if not value:
        return ""
    return value[:MAX_PATH]


def _parse_headers(header_lines):
    """Return [{name, value}] for allowlisted headers only."""
    result = []
    if not header_lines:
        return result
    for line in header_lines:
        try:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip().lower()
            if name in HEADER_ALLOWLIST:
                result.append({"name": name, "value": _redact(value)})
        except Exception:
            continue
    return result


def _param_names(parameters, want_body):
    """Collect parameter NAMES only; values are never read. Cookies excluded."""
    names = []
    seen = set()
    if not parameters:
        return names
    for param in parameters:
        try:
            ptype = param.getType()
            if want_body:
                if ptype == IParameter.PARAM_URL or ptype == IParameter.PARAM_COOKIE:
                    continue
            else:
                if ptype != IParameter.PARAM_URL:
                    continue
            name = param.getName()
            if not name:
                continue
            name = name[:200]
            if name not in seen:
                seen.add(name)
                names.append(name)
        except Exception:
            continue
    return names


def _url_parts(request_info):
    """Return (host, truncated path, query-free URL)."""
    host, path, safe_url = "", "", ""
    try:
        url = request_info.getUrl()
        if url is not None:
            host = url.getHost() or ""
            path = _safe_path(url.getPath() or "")
            scheme = url.getProtocol() or "http"
            authority = host
            port = url.getPort()
            if port not in (-1, 0, None):
                authority = host + ":" + str(port)
            safe_url = scheme + "://" + authority + path
    except Exception:
        pass
    if not host:
        try:
            for line in request_info.getHeaders():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()[:200]
                    break
        except Exception:
            pass
    return host, path, safe_url


def _build_item(helpers, message, message_is_request):
    request_info = helpers.analyzeRequest(message)
    host, path, safe_url = _url_parts(request_info)
    params = request_info.getParameters()
    request_headers = _parse_headers(request_info.getHeaders())

    item = {
        "method": request_info.getMethod() or "",
        "url": safe_url,
        "host": host,
        "path": path,
        "queryParams": _param_names(params, False),
        "bodyParams": _param_names(params, True),
        "headers": request_headers,
        "status": None,
        "contentType": "",
        "mimeType": "",
        "length": 0,
        "source": "live",
    }

    if message_is_request:
        try:
            item["length"] = len(message.getRequest())
        except Exception:
            pass
        for header in request_headers:
            if header["name"] == "content-type":
                item["contentType"] = header["value"]
                break
    else:
        try:
            item["length"] = len(message.getResponse())
        except Exception:
            pass
        response_info = helpers.analyzeResponse(message)
        item["status"] = response_info.getStatusCode()
        item["mimeType"] = response_info.getMimeType() or ""
        merged = _parse_headers(response_info.getHeaders())
        have = set(header["name"] for header in merged)
        for header in request_headers:
            if header["name"] not in have:
                merged.append(header)
        item["headers"] = merged
        for header in merged:
            if header["name"] == "content-type":
                item["contentType"] = header["value"]
                break
    return item


def _post(payload):
    """Best-effort POST; swallow every error so Burp traffic is never blocked."""
    try:
        data = json.dumps(payload)
        request = urllib2.Request(BRIDGE_URL, data, {"Content-Type": "application/json"})
        response = urllib2.urlopen(request, timeout=TIMEOUT_SECONDS)
        response.close()
    except Exception:
        pass


def _post_async(payload):
    try:
        worker = threading.Thread(target=_post, args=(payload,))
        worker.setDaemon(True)
        worker.start()
    except Exception:
        pass


class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("VAPT Lens Bridge Feeder")
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        try:
            item = _build_item(self._helpers, message, bool(messageIsRequest))
            _post_async(item)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ALTERNATIVE: log to a local file if Jython is unavailable
# ---------------------------------------------------------------------------
# Without Jython, do not install this extension. Use Burp's built-in logging:
#   Project options > Misc > Logging > Proxy requests/responses (enable),
#   or Proxy > HTTP history -> right-click -> Save selected items (XML/HAR),
# then paste the exported file into the extension's "Burp traffic" tab.
#
# If Jython loads but you prefer a file over HTTP, swap `_post_async(item)` in
# processProxyMessage for a local append like this:
#
#   import os
#   LOG_PATH = os.path.expanduser("~/vapt-lens-burp.jsonl")
#
#   def _append_to_file(item):
#       try:
#           with open(LOG_PATH, "a") as handle:
#               handle.write(json.dumps(item) + "\n")
#       except Exception:
#           pass
