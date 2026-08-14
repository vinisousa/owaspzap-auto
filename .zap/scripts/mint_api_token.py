#!/usr/bin/env python3
"""Mint a bearer token for a low-privileged account via the API's login endpoint.

Feeds API_AUTH_HEADER_VALUE_LOWPRIV for api_authz_probe.py's BFLA check,
without needing a manually obtained (and eventually expiring) static
token. Finds the login operation in the OpenAPI spec, maps its request
schema's field names to username/password, logs in with the given
credentials, and searches the JSON response for a token field.

Never fails the job: any problem (spec unreachable, no login-like path,
bad credentials, unrecognized response shape) is logged as a warning
and simply leaves API_AUTH_HEADER_VALUE_LOWPRIV unset, so the BFLA
probe skips itself exactly like it does when this step isn't run at
all. On failure to locate a token, only the response's key names are
logged - never values, since the response is exactly the kind of
payload that might carry the credentials or token itself.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin

TIMEOUT_SECONDS = 15
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "authenticate", "auth")
USERNAME_FIELD_HINTS = ("username", "user", "email", "login")
PASSWORD_FIELD_HINTS = ("password", "pass", "pwd")
TOKEN_KEY_HINTS = (
    "token",
    "access_token",
    "accesstoken",
    "jwt",
    "authtoken",
    "id_token",
    "idtoken",
    "sessiontoken",
    "auth_token",
)


def http_request(
    url: str, method: str, headers: dict[str, str], body: bytes | None = None
) -> tuple[int | None, bytes | None, str | None]:
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


def resolve_ref(schema: dict, spec: dict, depth: int = 0) -> dict:
    if depth > 10 or "$ref" not in schema:
        return schema
    node = spec
    for part in schema["$ref"].lstrip("#/").split("/"):
        node = node.get(part, {})
    return resolve_ref(node, spec, depth + 1)


def find_login_operation(spec: dict) -> tuple[str | None, dict | None]:
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        if not any(hint in path.lower() for hint in LOGIN_PATH_HINTS):
            continue
        op = item.get("post")
        if isinstance(op, dict):
            return path, op
    return None, None


def find_field(properties: dict, hints: tuple[str, ...]) -> str | None:
    for name in properties:
        if any(hint in name.lower() for hint in hints):
            return name
    return None


def find_token(obj, depth: int = 0) -> str | None:
    if depth > 2 or not isinstance(obj, dict):
        return None
    for key, value in obj.items():
        if isinstance(value, str) and value and key.lower() in TOKEN_KEY_HINTS:
            return value
    for value in obj.values():
        if isinstance(value, dict):
            found = find_token(value, depth + 1)
            if found:
                return found
    return None


def main() -> int:
    openapi_url = os.environ["OPENAPI_URL"]
    api_target_url = os.environ["API_TARGET_URL"]
    username = os.environ["LOWPRIV_USERNAME"]
    password = os.environ["LOWPRIV_PASSWORD"]
    header_prefix = os.environ.get("LOWPRIV_TOKEN_PREFIX", "Bearer ")

    status, body, err = http_request(openapi_url, "GET", {})
    if err or status is None or status >= 400 or body is None:
        print(
            f"::warning::Could not fetch the OpenAPI spec to mint a low-priv token "
            f"({err or status}) - the BFLA probe will be skipped."
        )
        return 0
    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        print("::warning::OpenAPI spec is not valid JSON - the BFLA probe will be skipped.")
        return 0

    servers = spec.get("servers")
    base_url = (servers[0].get("url") if servers else None) or api_target_url
    base_url = base_url.rstrip("/")

    path, op = find_login_operation(spec)
    if path is None or op is None:
        print(
            "::warning::No login-like path (post + 'login'/'auth' in the URL) found in "
            "the OpenAPI spec - the BFLA probe will be skipped."
        )
        return 0

    schema = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
    schema = resolve_ref(schema, spec)
    properties = schema.get("properties", {})

    username_field = find_field(properties, USERNAME_FIELD_HINTS) or "username"
    password_field = find_field(properties, PASSWORD_FIELD_HINTS) or "password"

    payload = {username_field: username, password_field: password}
    url = urljoin(base_url + "/", path.lstrip("/"))
    status, resp_body, err = http_request(url, "POST", {}, body=json.dumps(payload).encode())

    if err:
        print(f"::warning::Login request to {path} failed ({err}) - the BFLA probe will be skipped.")
        return 0
    if status is None or status >= 400:
        print(f"::warning::Login to {path} returned {status} - the BFLA probe will be skipped.")
        return 0

    try:
        resp_json = json.loads(resp_body) if resp_body else {}
    except json.JSONDecodeError:
        print(f"::warning::Login response from {path} was not JSON - the BFLA probe will be skipped.")
        return 0

    token = find_token(resp_json)
    if not token:
        print(
            f"::warning::Logged in via {path} but found no token field in the response "
            f"(top-level keys: {sorted(resp_json.keys()) if isinstance(resp_json, dict) else 'n/a'}) "
            "- the BFLA probe will be skipped."
        )
        return 0

    print(f"::add-mask::{token}")
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a") as f:
            f.write(f"API_AUTH_HEADER_VALUE_LOWPRIV={header_prefix}{token}\n")
    print(f"Minted a low-privileged token via POST {path} (username field '{username_field}').")
    return 0


if __name__ == "__main__":
    sys.exit(main())
