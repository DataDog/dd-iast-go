#!/usr/bin/env python3
"""Replays the system-tests IAST assertions (tests/appsec/iast/utils.py @ 4dcd3b8)
against the event JSON captured by zz_systemtests_shape_test.go, and validates each
event against tests/appsec/iast/vulnerability_schema.json.

usage: check_shapes.py shapes.json vulnerability_schema.json
"""
import json
import sys

import jsonschema

shapes = json.load(open(sys.argv[1]))
schema = json.load(open(sys.argv[2]))
validator = jsonschema.Draft7Validator(schema)
by_name = {c["name"]: c for c in shapes}

# The harness JSON-encodes the in-memory _dd.stack value, whose Go structs carry
# only msgp tags; map Go field names to the msgp wire names system-tests sees.
_WIRE = {"Frames": "frames", "File": "file", "Namespace": "namespace", "ClassName": "class_name",
         "Function": "function", "Line": "line", "ID": "id", "Language": "language", "Index": "id_frame"}


def _norm(value):
    if isinstance(value, dict):
        return {_WIRE.get(k, k): _norm(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


for _c in shapes:
    if _c.get("stack"):
        _c["stack"] = _norm(_c["stack"])


def event(name):
    return by_name[name].get("event")


def vulns(name, vtype=None):
    ev = event(name) or {}
    return [v for v in ev.get("vulnerabilities", []) if vtype is None or v["type"] == vtype]


def source_check(name, origin, names=None, value=None):
    """Mirror of BaseSourceTest.validate_request_reported."""
    ev = event(name)
    if not ev:
        return "FAIL: no IAST event"
    sources = ev.get("sources", [])
    if not sources:
        return "FAIL: no source reported"
    if origin not in {s.get("origin") for s in sources}:
        return f"FAIL: origin {origin} not in {[s.get('origin') for s in sources]}"
    sources = [s for s in sources if s["origin"] == origin]
    if names:
        if not any(n in names for n in {s.get("name") for s in sources}):
            return f"FAIL: names {names} not in {sources}"
        sources = [s for s in sources if s.get("name") in names]
    if value:
        if value not in {s.get("value") for s in sources}:
            return f"FAIL: value {value!r} not in {sources}"
        sources = [s for s in sources if s.get("value") == value]
    if len(sources) != 1:
        return f"FAIL: expected single source, got {sources}"
    return f"PASS ({sources[0]})"


def sink_check(insecure, secure, vtype, location=None, evidence=None):
    vs = vulns(insecure, vtype)
    if not vs:
        return f"FAIL insecure: no {vtype}"
    if location:
        vs = [v for v in vs if v.get("location", {}).get("path", "") == location]
        if not vs:
            return f"FAIL insecure: no location {location}"
    if evidence:
        vs = [v for v in vs if v.get("evidence", {}).get("value", "") == evidence]
        if not vs:
            return f"FAIL insecure: no evidence {evidence}"
    res = f"PASS insecure ({len(vs)} vuln)"
    if secure:
        if vulns(secure, vtype):
            res += f"; FAIL secure: {vulns(secure, vtype)}"
        else:
            res += "; PASS secure"
    return res


def go_frame_names(frame):
    class_name = frame.get("class_name", "")
    method = frame.get("function", "")
    ns = frame.get("namespace", "")
    if ns:
        if class_name:
            class_name = f"{ns}.{class_name}"
        elif method:
            method = f"{ns}.{method}"
    return class_name, method


def stack_check(name, vtype):
    """Mirror of validate_stack_traces + validate_extended_location_data (go branch)."""
    vs = vulns(name, vtype)
    if not vs:
        return "FAIL: no vuln"
    stack = by_name[name].get("stack")
    if not stack:
        return "FAIL: no _dd.stack"
    traces = stack.get("vulnerability") if isinstance(stack, dict) else None
    if not traces:
        return f"FAIL: no vulnerability stacks in {type(stack)}"
    out = []
    if len(vs) != 1:
        out.append(f"FAIL extended: {len(vs)} vulns of type")
    v = vs[0]
    loc = v.get("location", {})
    sid = loc.get("stackId")
    tr = [t for t in traces if t.get("id") == sid]
    if not tr:
        return f"FAIL: stackId {sid} not in traces"
    t = tr[0]
    frames = t.get("frames", [])
    if t.get("language") != "go":
        out.append(f"FAIL: language={t.get('language')}")
    if len(frames) > 32:
        out.append(f"FAIL: {len(frames)} frames > 32")
    found = None
    for f in frames:
        cls, meth = go_frame_names(f)
        if loc.get("path") == f.get("file") and loc.get("line") == f.get("line") and loc.get("class", "") == cls and loc.get("method") == meth:
            found = f
            break
    out.append("PASS location-in-stack" if found else f"FAIL location {loc} not in frames[0..2]={frames[:3]}")
    out.append(f"frames={len(frames)} location={loc}")
    return "; ".join(out)


print("== schema validation (Draft7, like TestIastVulnerabilitySchema) ==")
for c in shapes:
    ev = c.get("event")
    if not ev:
        print(f"{c['name']:40s} no event (enabled={c.get('enabled')}, status={c['status']}{', ' + c['note'] if c.get('note') else ''})")
        continue
    errs = list(validator.iter_errors(ev))
    print(f"{c['name']:40s} {'VALID' if not errs else 'INVALID: ' + '; '.join(e.message for e in errs)}")

print("\n== system-tests assertions ==")
checks = {
    "control: SQL direct source, no concat": lambda: sink_check("sqli_direct_nonconcat", None, "SQL_INJECTION"),
    "control: SQL concat inside _test.go": lambda: sink_check("sqli_testfile_concat", None, "SQL_INJECTION"),
    "TestSqlInjection.insecure/secure": lambda: sink_check("sqli_insecure", "sqli_secure", "SQL_INJECTION"),
    "TestSqlInjection_StackTrace/ExtendedLocation": lambda: stack_check("sqli_insecure", "SQL_INJECTION"),
    "TestCommandInjection.insecure/secure": lambda: sink_check("cmdi_insecure", "cmdi_secure", "COMMAND_INJECTION"),
    "TestCommandInjection_StackTrace/ExtendedLocation": lambda: stack_check("cmdi_insecure", "COMMAND_INJECTION"),
    "TestWeakHash.insecure (evidence MD5)": lambda: sink_check("weak_hash_md5", None, "WEAK_HASH", evidence="MD5"),
    "TestWeakHash_StackTrace/ExtendedLocation": lambda: stack_check("weak_hash_md5", "WEAK_HASH"),
    "TestWeakCipher.insecure": lambda: sink_check("weak_cipher_rc4", None, "WEAK_CIPHER"),
    "TestWeakCipher_StackTrace/ExtendedLocation": lambda: stack_check("weak_cipher_rc4", "WEAK_CIPHER"),
    "TestHeaderValue": lambda: source_check("source_header_value", "http.request.header", None, "user"),
    "TestHeaderValue (intended name 'table')": lambda: source_check("source_header_value", "http.request.header", ["table"], "user"),
    "TestHeaderName": lambda: source_check("source_header_name", "http.request.header.name"),
    "TestHeaderName (intended name 'user')": lambda: source_check("source_header_name", "http.request.header.name", ["user"]),
    "TestCookieName": lambda: source_check("source_cookie_name", "http.request.cookie.name", ["table"], "table"),
    "TestCookieValue": lambda: source_check("source_cookie_value", "http.request.cookie.value", ["table"], "user"),
    "TestParameterName GET": lambda: source_check("source_parameter_name_get", "http.request.parameter.name", ["user"]),
    "TestParameterName POST": lambda: source_check("source_parameter_name_post", "http.request.parameter.name", ["user"]),
    "TestParameterValue GET (FormValue)": lambda: source_check("source_parameter_value_get_formvalue", "http.request.parameter", ["table"], "user"),
    "TestParameterValue GET (URL.Query)": lambda: source_check("source_parameter_value_get_urlquery", "http.request.parameter", ["table"], "user"),
    "TestParameterValue POST": lambda: source_check("source_parameter_value_post", "http.request.parameter", ["table"], "user"),
    "TestPath": lambda: source_check("source_path", "http.request.path", None, "/iast/source/path/test"),
    "TestPathParameter": lambda: source_check("source_path_parameter", "http.request.path.parameter", ["table"], "user"),
    "TestURI (RequestURI)": lambda: source_check("source_uri_requesturi", "http.request.uri", None, "http://localhost:7777/iast/source/uri/test"),
    "TestURI (URL.String)": lambda: source_check("source_uri_urlstring", "http.request.uri", None, "http://localhost:7777/iast/source/uri/test"),
    "TestRequestBody": lambda: source_check("source_body_json", "http.request.body"),
    "TestMultipart": lambda: source_check("source_multipart_file", "http.request.multipart.parameter", ["name", "Content-Disposition"]),
}
for label, fn in checks.items():
    try:
        print(f"{label:52s} {fn()}")
    except Exception as e:  # keep every failure visible
        print(f"{label:52s} ERROR {type(e).__name__}: {e}")
