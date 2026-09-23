import glob, json, sys
import jsonschema

schema = json.load(open("/Users/eliott.bouhana/go/src/github.com/DataDog/system-tests/tests/appsec/iast/vulnerability_schema.json"))
status = 0
for path in sorted(glob.glob(sys.argv[1] + "/span_iast_json_prefix*.json")):
    event = json.load(open(path))
    parts = event["vulnerabilities"][0]["evidence"]["valueParts"]
    summary = [{k: (v if k != "value" else f"<{len(v)} chars>") for k, v in p.items()} for p in parts]
    try:
        jsonschema.validate(event, schema)
        print(f"{path.split('/')[-1]}: SCHEMA_VALID parts={summary}")
    except jsonschema.ValidationError as err:
        status = 1
        print(f"{path.split('/')[-1]}: SCHEMA_INVALID at {list(err.absolute_path)}: {err.message[:160]} parts={summary}")
sys.exit(status)
