#!/usr/bin/env python3
"""BFLA / BOPLA differential authorization probe.

Complements the ZAP scan with two checks that have no job type in the
ZAP Automation Framework and therefore can't be added as another
`- type: ...` entry in the plan:

  * BFLA (OWASP API5) - Broken Function Level Authorization
    Replays every path+method declared in the OpenAPI spec using a
    second, lower-privileged credential, and flags any call that still
    succeeds (2xx). A low-privileged identity reaching an endpoint at
    all is the signal here.

  * BOPLA (OWASP API3) - Broken Object Property Level Authorization
    For write endpoints (POST/PUT/PATCH) with a JSON request body,
    builds a minimal payload from the declared schema, adds properties
    that are NOT part of that schema (role, isAdmin, permissions, ...),
    and flags calls that still succeed - a mass-assignment signal.

This is a heuristic differential probe, not the ZAP "Access Control
Testing" add-on (which requires a hand-curated access matrix and has
no Automation Framework job either). Findings need human review; a 2xx
here means "look at this", not "this is definitely a vulnerability".

True BOLA (same endpoint, a resource ID owned by someone else) is out
of scope: it requires knowing which object IDs belong to which user,
which can't be inferred from the OpenAPI spec alone.

No third-party dependencies - stdlib only, so it runs on a bare
ubuntu-latest runner without an extra pip install step.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin

TIMEOUT_SECONDS = 15
PATH_PARAM_PLACEHOLDER = "1"
# Some targets sit behind a WAF that blocks Python's default "Python-urllib/x.y"
# User-Agent outright (observed here: a 406 on the OpenAPI spec URL itself). A
# browser-like value avoids that easy fingerprint without pretending to be ZAP.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
WRITE_METHODS = ("post", "put", "patch")
ALL_METHODS = ("get", "post", "put", "patch", "delete")

# Properties injected into write requests to probe for mass assignment.
# Chosen to be plausible escalation targets across typical REST APIs.
ESCALATION_PROPERTIES = {
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "permissions": ["admin"],
    "userType": "admin",
    "accountType": "admin",
    "balance": 999999,
    "price": 0,
    "discount": 100,
    "verified": True,
    "is_verified": True,
}


@dataclass
class Finding:
    check: str
    method: str
    path: str
    detail: str
    status_code: int | None
    severity: str


@dataclass
class ProbeResult:
    findings: list[Finding] = field(default_factory=list)
    bfla_endpoints_tested: int = 0
    bopla_endpoints_tested: int = 0
    errors: list[str] = field(default_factory=list)


def http_request(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None = None,
) -> tuple[int | None, bytes | None, str | None]:
    """Returns (status_code, response_body, error_message)."""
    req = urllib.request.Request(url, data=body, method=method.upper())
    req.add_header("User-Agent", DEFAULT_USER_AGENT)
    for key, value in headers.items():
        req.add_header(key, value)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(), None
    except urllib.error.HTTPError as e:
        return e.code, e.read(), None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        return None, None, str(e)


def resolve_base_url(spec: dict, fallback: str) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url")
        if url:
            return url.rstrip("/")
    return fallback.rstrip("/")


def substitute_path_params(path: str) -> str:
    return re.sub(r"\{[^}/]+\}", PATH_PARAM_PLACEHOLDER, path)


def build_sample_value(schema: dict):
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    schema_type = schema.get("type")
    if schema_type == "string":
        return "test"
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        items = schema.get("items", {})
        return [build_sample_value(items)] if items else []
    if schema_type == "object":
        return build_sample_object(schema)
    return "test"


def build_sample_object(schema: dict) -> dict:
    props = schema.get("properties", {})
    obj = {}
    for name, prop_schema in props.items():
        obj[name] = build_sample_value(prop_schema)
    return obj


def get_json_body_schema(operation: dict, spec: dict) -> dict | None:
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return None
    content = request_body.get("content", {})
    json_content = content.get("application/json")
    if not isinstance(json_content, dict):
        return None
    schema = json_content.get("schema")
    if not isinstance(schema, dict):
        return None
    return resolve_ref(schema, spec)


def resolve_ref(schema: dict, spec: dict, _depth: int = 0) -> dict:
    if _depth > 10:
        return schema
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return schema
        node = spec
        for part in ref.lstrip("#/").split("/"):
            node = node.get(part, {})
        return resolve_ref(node, spec, _depth + 1)
    return schema


def probe_bfla(
    spec: dict,
    base_url: str,
    header_name: str,
    normal_auth: str,
    lowpriv_auth: str,
    result: ProbeResult,
) -> None:
    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        concrete_path = substitute_path_params(path)
        url = urljoin(base_url + "/", concrete_path.lstrip("/"))
        for method in ALL_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            result.bfla_endpoints_tested += 1

            normal_status, _, normal_err = http_request(
                url, method, {header_name: normal_auth}
            )
            lowpriv_status, _, lowpriv_err = http_request(
                url, method, {header_name: lowpriv_auth}
            )

            if lowpriv_err:
                result.errors.append(f"{method.upper()} {path} (low-priv): {lowpriv_err}")
                continue

            if lowpriv_status is not None and 200 <= lowpriv_status < 300:
                severity = "high" if method in WRITE_METHODS else "medium"
                result.findings.append(
                    Finding(
                        check="BFLA",
                        method=method.upper(),
                        path=path,
                        detail=(
                            f"Low-privileged credential got {lowpriv_status} "
                            f"(normal credential got {normal_status if not normal_err else 'error: ' + normal_err})."
                        ),
                        status_code=lowpriv_status,
                        severity=severity,
                    )
                )


def probe_bopla(
    spec: dict,
    base_url: str,
    header_name: str,
    normal_auth: str,
    result: ProbeResult,
) -> None:
    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        concrete_path = substitute_path_params(path)
        url = urljoin(base_url + "/", concrete_path.lstrip("/"))
        for method in WRITE_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            schema = get_json_body_schema(operation, spec)
            if schema is None or schema.get("type") not in (None, "object"):
                continue
            result.bopla_endpoints_tested += 1

            baseline_body = build_sample_object(schema)
            declared_props = set(schema.get("properties", {}).keys())
            injected = {
                k: v for k, v in ESCALATION_PROPERTIES.items() if k not in declared_props
            }
            if not injected:
                continue
            tampered_body = {**baseline_body, **injected}

            status, resp_body, err = http_request(
                url,
                method,
                {header_name: normal_auth},
                body=json.dumps(tampered_body).encode(),
            )
            if err:
                result.errors.append(f"{method.upper()} {path} (BOPLA): {err}")
                continue

            if status is not None and 200 <= status < 300:
                echoed = []
                if resp_body:
                    try:
                        resp_json = json.loads(resp_body)
                        if isinstance(resp_json, dict):
                            echoed = [k for k in injected if k in resp_json]
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
                severity = "high" if echoed else "medium"
                detail = f"Request with extra properties {sorted(injected)} got {status}."
                if echoed:
                    detail += f" Server echoed back: {sorted(echoed)}."
                result.findings.append(
                    Finding(
                        check="BOPLA",
                        method=method.upper(),
                        path=path,
                        detail=detail,
                        status_code=status,
                        severity=severity,
                    )
                )


def write_reports(output_json: str, output_md: str, result: ProbeResult) -> None:
    high = [f for f in result.findings if f.severity == "high"]
    medium = [f for f in result.findings if f.severity == "medium"]

    with open(output_json, "w") as f:
        json.dump(
            {
                "bfla_endpoints_tested": result.bfla_endpoints_tested,
                "bopla_endpoints_tested": result.bopla_endpoints_tested,
                "findings": [vars(f) for f in result.findings],
                "errors": result.errors,
            },
            f,
            indent=2,
        )

    with open(output_md, "w") as f:
        f.write("# BFLA / BOPLA differential authorization probe\n\n")
        f.write(
            "Heuristic probe, not the ZAP Access Control Testing add-on. "
            "Every finding below needs human review before being treated as a real vulnerability.\n\n"
        )
        f.write(f"- BFLA endpoints tested: {result.bfla_endpoints_tested}\n")
        f.write(f"- BOPLA endpoints tested: {result.bopla_endpoints_tested}\n")
        f.write(f"- High-severity findings: {len(high)}\n")
        f.write(f"- Medium-severity findings: {len(medium)}\n")
        f.write(f"- Request errors: {len(result.errors)}\n\n")
        if result.findings:
            f.write("| Severity | Check | Method | Path | Detail |\n")
            f.write("|---|---|---|---|---|\n")
            for finding in sorted(result.findings, key=lambda x: x.severity):
                f.write(
                    f"| {finding.severity} | {finding.check} | {finding.method} | "
                    f"`{finding.path}` | {finding.detail} |\n"
                )
        else:
            f.write("No findings.\n")

    print(f"BFLA endpoints tested: {result.bfla_endpoints_tested}")
    print(f"BOPLA endpoints tested: {result.bopla_endpoints_tested}")
    print(f"High-severity findings: {len(high)}")
    print(f"Medium-severity findings: {len(medium)}")
    for finding in result.findings:
        print(f"::warning::[{finding.severity.upper()} {finding.check}] {finding.method} {finding.path} - {finding.detail}")
    for error in result.errors:
        print(f"::warning::[authz-probe request error] {error}")

    print(f"authz_high_count={len(high)}")
    print(f"authz_medium_count={len(medium)}")


def main() -> int:
    openapi_url = os.environ["OPENAPI_URL"]
    api_target_url = os.environ["API_TARGET_URL"]
    header_name = os.environ.get("API_AUTH_HEADER_NAME", "Authorization")
    normal_auth = os.environ["API_AUTH_HEADER_VALUE"]
    lowpriv_auth = os.environ.get("API_AUTH_HEADER_VALUE_LOWPRIV", "")
    output_json = os.environ.get("AUTHZ_PROBE_OUTPUT_JSON", "authz-probe-report.json")
    output_md = os.environ.get("AUTHZ_PROBE_OUTPUT_MD", "authz-probe-report.md")

    status, body, err = http_request(openapi_url, "GET", {})
    if err or status is None or status >= 400 or body is None:
        # Non-fatal by design: this probe is best-effort and additive to the ZAP
        # scan, so a spec we can't fetch (e.g. blocked by the same WAF that also
        # trips up ZAP sometimes) shouldn't fail the job - just skip the probe.
        print(f"::warning::Could not fetch OpenAPI spec for the authz probe: {err or status} - skipping.")
        write_reports(output_json, output_md, ProbeResult())
        return 0
    try:
        spec = json.loads(body)
    except json.JSONDecodeError as e:
        print(f"::warning::OpenAPI spec is not valid JSON, skipping the authz probe: {e}")
        write_reports(output_json, output_md, ProbeResult())
        return 0

    base_url = resolve_base_url(spec, api_target_url)
    result = ProbeResult()

    if lowpriv_auth:
        probe_bfla(spec, base_url, header_name, normal_auth, lowpriv_auth, result)
    else:
        print(
            "No API_AUTH_HEADER_VALUE_LOWPRIV configured - skipping the BFLA probe "
            "(set the ZAP_API_AUTH_HEADER_VALUE_LOWPRIV secret to enable it)."
        )

    probe_bopla(spec, base_url, header_name, normal_auth, result)

    write_reports(output_json, output_md, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
