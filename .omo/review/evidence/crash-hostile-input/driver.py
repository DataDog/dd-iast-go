#!/usr/bin/env python3
"""Hostile-input driver for the woven cmd/hostile app."""
import json, socket, sys, time, os, subprocess, concurrent.futures as cf

HOST, PORT = "127.0.0.1", int(os.environ.get("PORT", "18089"))
PID = int(os.environ.get("APP_PID", "0"))


def raw(req: bytes, timeout=120):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.sendall(req)
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data.split(b"\r\n", 1)[0].decode("latin1")
    except Exception as e:  # noqa
        return f"ERR {e!r}"
    finally:
        s.close()


def req(method, path, headers=None, body=b""):
    h = [f"{method} ".encode() + path + b" HTTP/1.1", b"Host: x", b"Connection: close"]
    for k, v in (headers or []):
        h.append(k + b": " + v)
    if body:
        h.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(h) + b"\r\n\r\n" + body


def get(path):
    return raw(req("GET", path.encode() if isinstance(path, str) else path))


def http_json(path):
    s = socket.create_connection((HOST, PORT), timeout=120)
    s.sendall(req("GET", path.encode()))
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(1 << 20)
        if not c:
            break
        data += c
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        out, rest = b"", body
        while rest:
            size_s, _, rest = rest.partition(b"\r\n")
            n = int(size_s, 16)
            if n == 0:
                break
            out += rest[:n]
            rest = rest[n + 2:]
        body = out
    return json.loads(body)


def rss_kb():
    if not PID:
        return -1
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(PID)], capture_output=True, text=True).stdout.strip()
    return int(out or -1)


SECRET_BEARER = b"Bearer abcdefghijklmnopqrstuvwxyzSECRETBEARER"
INV = b"\xff\xfe\xc3\x28\xa0\xa1\xe2\x28\xa1\xf0\x28\x8c\xbc\xed\xa0\x80"


def cases():
    c = {}
    # ---- headers
    c["hdr_1mb_single"] = req("GET", b"/h", [(b"X-Big", b"A" * (1 << 20) - 0 if False else b"A" * 1_040_000)])
    c["hdr_1mb_invalid_utf8"] = req("GET", b"/h", [(b"X-Big", (INV * 65000)[:1_040_000])])
    c["hdr_32x30k"] = req("GET", b"/h", [(f"X-H{i}".encode(), (b"v%d-" % i) + INV + b"x" * 30000) for i in range(31)] + [(b"Authorization", SECRET_BEARER)])
    c["hdr_64k_edge"] = req("GET", b"/h", [(b"X-Big", b"B" * 65536), (b"X-Cmd", b"ls " + INV)])
    c["hdr_64k_plus1"] = req("GET", b"/h", [(b"X-Big", b"B" * 65537)])
    c["hdr_2000_names"] = req("GET", b"/h", [(f"X-N{i}".encode(), INV + b"%d" % i) for i in range(2000)])
    c["hdr_secret_small"] = req("GET", b"/h?password=hunter2SECRETPW&x=1", [(b"Authorization", SECRET_BEARER), (b"X-Cmd", b"--password=SECRETCMD"), (b"X-Big", b"SECRETLITERAL\xff")])
    c["hdr_invalid_name_utf8"] = req("GET", b"/h", [(b"X-\xff\xfe", b"v")])
    # ---- query
    qs = "&".join(f"p{i}=v{i}%FF%FE" for i in range(10000))
    c["q_10k_params"] = req("GET", b"/q?" + qs.encode() + b"&a=%FF%FE%C3%28&cmd=%00%FF")
    qs2 = "&".join(f"p{i}=v{i}" for i in range(20000))
    c["q_20k_params"] = req("GET", b"/q?" + qs2.encode())
    c["q_invalid_raw_bytes"] = req("GET", b"/q?a=" + INV * 10 + b"&cmd=" + INV)
    c["q_40_params_utf8"] = req("GET", b"/q?" + b"&".join(b"k%d=%%FF%%FE%d" % (i, i) for i in range(40)) + b"&a=SECRETQ%FF&password=SECRETPWQ")
    c["q_huge_value"] = req("GET", b"/q?a=" + b"Z" * 1_000_000)
    c["q_60k_value"] = req("GET", b"/q?a=" + b"%FF" * 20000)
    c["q_bad_escapes"] = req("GET", b"/q?a=%%%%%ZZ%F&%=%&&&==&a=%u1234")
    # ---- form
    fb = "&".join(f"f{i}=v{i}%FF" for i in range(10000)).encode() + b"&a=x%FF"
    c["form_10k"] = req("POST", b"/form", [(b"Content-Type", b"application/x-www-form-urlencoded")], fb)
    c["form_40_invalid"] = req("POST", b"/form?q=1", [(b"Content-Type", b"application/x-www-form-urlencoded")], b"&".join(b"f%d=%%FF%%C3%d" % (i, i) for i in range(40)) + b"&a=" + b"%FE" * 5000)
    c["form_9mb"] = req("POST", b"/form", [(b"Content-Type", b"application/x-www-form-urlencoded")], b"a=" + b"Q" * 9_000_000)
    # ---- multipart
    def mp(nparts, fname_len=10, nfiles=0, value=b"val"):
        B = b"XXBOUNDARYXX"
        parts = []
        for i in range(nparts):
            parts.append(b"--" + B + b"\r\nContent-Disposition: form-data; name=\"a%d\"\r\n\r\n" % i + value + INV + b"\r\n")
        for i in range(nfiles):
            parts.append(b"--" + B + b"\r\nContent-Disposition: form-data; name=\"file%d\"; filename=\"" % i + (b"f" + INV) * (fname_len // 17 + 1) + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n" + b"D" * 100 + b"\r\n")
        parts.append(b"--" + B + b"\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n" + b"SECRETMP" + INV + b"\r\n")
        body = b"".join(parts) + b"--" + B + b"--\r\n"
        return req("POST", b"/mp", [(b"Content-Type", b"multipart/form-data; boundary=" + B)], body)
    c["mp_5k_parts"] = mp(5000)
    c["mp_900_parts"] = mp(900)
    c["mp_40_parts"] = mp(40, value=b"v" * 30000)
    c["mp_huge_filenames"] = mp(5, fname_len=500_000, nfiles=10)
    c["mp_900_files"] = mp(0, fname_len=2000, nfiles=900)
    c["mp_malformed"] = req("POST", b"/mp", [(b"Content-Type", b"multipart/form-data; boundary=ZZ")], b"--ZZ\r\nContent-Disposition: form-data; name=\"a\r\n\r\nx\r\n--ZZ")
    # ---- readall
    c["readall_50mb"] = req("POST", b"/readall", [], b"R" * 50_000_000)
    c["readall_64k"] = req("POST", b"/readall", [], (b"SECRETBODY" + INV * 4000)[:65536])
    c["readall_invalid"] = req("POST", b"/readall", [], INV * 100)
    # ---- json
    deep = b'{"a":"x","d":' + b"[" * 9990 + b"]" * 9990 + b"}"
    deeper = b'{"a":"x","d":' + b"[" * 12000 + b"]" * 12000 + b"}"
    deepobj = b'{"a":"x","d":' + b'{"k":' * 9990 + b"1" + b"}" * 9990 + b"}"
    esc = b'{"a":"' + b"\\u0041\\n\\\"\\\\\\ud83d\\ude00\\udc00" * 20000 + b'","b":["' + b"\\t" * 20000 + b'"]}'
    esc_small = b'{"a":"' + b"\\u0041\\n\\\"\\\\\\ud83d\\ude00\\udc00" * 1000 + b'SECRETJSON","b":["x\\u00ff"]}'
    many = b'{"a":"x","b":[' + b",".join(b'"s%d\\u00e9"' % i for i in range(10000)) + b'],"c":{' + b",".join(b'"k%d":"v%d"' % (i, i) for i in range(10000)) + b"}}"
    huge_str = b'{"a":"' + b"H" * 5_000_000 + b'"}'
    inv_json = b'{"a":"' + INV * 100 + b'","c":{"\xff":"\xfe"}}'
    for name, doc in [("deep9990", deep), ("deep12000", deeper), ("deepobj", deepobj), ("escapes", esc), ("escapes_small", esc_small), ("many", many), ("huge_str", huge_str), ("invalid_utf8", inv_json)]:
        c["json_" + name] = req("POST", b"/json", [(b"Content-Type", b"application/json")], doc)
        c["jsonu_" + name] = req("POST", b"/jsonu", [(b"Content-Type", b"application/json")], doc)
    # ---- cookies
    odd = b'; '.join([b"a=b", b"", b"=", b'a="quoted"', b"a=\xff\xfe", b"===", b'"a"=b', b"a=1;a=2", b"$Version=1", b"a", b" a = b ", b"a=\x01\x7f", b"SECRET=SECRETCOOKIE"])
    c["cookie_odd"] = req("GET", b"/cookie", [(b"Cookie", odd)])
    odd2 = b'; '.join([b"a=b", b"", b"=", b'a="quoted"', b"a=\xff\xfe", b"===", b'"a"=b', b"a=1;a=2", b"$Version=1", b"a", b" a = b ", b"SECRET=SECRETCOOKIE", b"a=" + INV])
    c["cookie_odd_noctl"] = req("GET", b"/cookie", [(b"Cookie", odd2)])
    c["cookie_5k"] = req("GET", b"/cookie", [(b"Cookie", b"; ".join(b"c%d=v%d" % (i, i) for i in range(5000)) + b"; a=last")])
    c["cookie_900k_value"] = req("GET", b"/cookie", [(b"Cookie", b"a=" + b"C" * 900_000)])
    c["cookie_multi_header"] = req("GET", b"/cookie", [(b"Cookie", b"a=%d" % i) for i in range(1000)])
    # ---- propagation
    for n in [16, 1024, 8192]:
        c[f"prop_{n}"] = req("GET", b"/prop?a=" + (b"%FFa,b%20c%26" * (n // 13 + 1))[: n * 3])
    c["prop_hdr_invalid"] = req("GET", b"/prop", [(b"X-A", INV * 50 + b", a,b & c")])
    c["exploit_sqli"] = req("GET", b"/exploit?param=%27%20OR%20TRUE%20--")
    c["exploit_sqli_num"] = req("GET", b"/exploit?param=1%20OR%201%3D1")
    return c


def main():
    rounds = int(os.environ.get("ROUNDS", "3"))
    conc = int(os.environ.get("CONC", "8"))
    all_cases = cases()
    sel = os.environ.get("CASES")
    if sel:
        all_cases = {k: v for k, v in all_cases.items() if any(k.startswith(p) for p in sel.split(","))}
    print("baseline", json.dumps(http_json("/stats")), "rss_kb", rss_kb(), flush=True)
    http_json("/spans")
    # serial pass, per-case measurements
    for name, r in all_cases.items():
        t = time.time()
        status = raw(r)
        dt = time.time() - t
        st = http_json("/stats")
        print(f"case {name:24s} bytes={len(r):>9d} status={status!r} t={dt:.2f}s heap_inuse={st['heap_inuse']} heap_objects={st['heap_objects']} rss_kb={rss_kb()} maxrss={st['maxrss']} gor={st['goroutines']} tainted_sinks={st['tainted_sinks']}/{st['sinks']}", flush=True)
    spans = http_json("/spans")
    with open(os.environ.get("SPANS_OUT", "/tmp/ddiast-review/wt/crash-hostile-input/out/spans.json"), "w") as f:
        json.dump(spans, f)
    print("spans", len(spans), "with_json", sum(1 for s in spans if s.get("json")), flush=True)
    # concurrent rounds for steady-state memory
    names = list(all_cases)
    for rd in range(rounds):
        t = time.time()
        with cf.ThreadPoolExecutor(conc) as ex:
            res = list(ex.map(lambda n: (n, raw(all_cases[n])), names))
        bad = [(n, s) for n, s in res if not s.startswith("HTTP/1.1 ")]
        http_json("/spans")
        st = http_json("/stats")
        print(f"round {rd} t={time.time()-t:.1f}s heap_inuse={st['heap_inuse']} heap_objects={st['heap_objects']} rss_kb={rss_kb()} maxrss={st['maxrss']} gor={st['goroutines']} bad={bad}", flush=True)


if __name__ == "__main__":
    main()
