"""Check a fixed Mihomo route against a local policy."""

import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import stat
from urllib.parse import quote


RULE_TYPES = {"domain", "domainsuffix", "processpath", "processpathregex"}
VERSION = "0.1.0"
NON_PROXY_TYPES = {"direct", "pass", "reject", "rejectdrop", "compatible"}
MAX_POLICY = 64 * 1024
MAX_RUNTIME = 4 * 1024 * 1024


class AuditInputError(Exception):
    """The audit could not read or interpret its inputs."""


def parse_object(raw):
    def unique_keys(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise AuditInputError("DUPLICATE_JSON_KEY")
            result[name] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique_keys)
    except (ValueError, RecursionError):
        raise AuditInputError("INVALID_JSON") from None
    if not isinstance(value, dict):
        raise AuditInputError("INVALID_JSON_OBJECT")
    return value


def read_object(path, limit):
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise AuditInputError("INPUT_NOT_REGULAR_FILE")
            raw = source.read(limit + 1)
    except OSError:
        raise AuditInputError("INPUT_UNREADABLE") from None
    if len(raw) > limit:
        raise AuditInputError("INPUT_TOO_LARGE")
    return parse_object(raw)


def identifier(value):
    return (isinstance(value, str) and 0 < len(value) <= 256 and value.isprintable()
            and value == value.strip() and value not in {".", ".."}
            and not any(char in value for char in "/\\"))


def rule_type(value):
    if not isinstance(value, str):
        return ""
    return value.lower().replace("-", "")


def validate_policy(policy):
    if (policy.keys() != {"group", "node", "tun", "rules"}
            or not identifier(policy["group"]) or not identifier(policy["node"])
            or policy["group"] == policy["node"] or type(policy["tun"]) is not bool
            or not isinstance(policy["rules"], list) or not 1 <= len(policy["rules"]) <= 128):
        raise AuditInputError("INVALID_POLICY")
    seen = set()
    for rule in policy["rules"]:
        if (not isinstance(rule, dict) or rule.keys() != {"type", "payload"}
                or rule_type(rule["type"]) not in RULE_TYPES or not isinstance(rule["payload"], str)
                or not rule["payload"].strip() or not rule["payload"].isprintable()):
            raise AuditInputError("INVALID_POLICY_RULE")
        key = (rule_type(rule["type"]), rule["payload"])
        if key in seen:
            raise AuditInputError("DUPLICATE_POLICY_RULE")
        seen.add(key)


class UnixController(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def socket_get(path, route, limit):
    with_socket = UnixController(path)
    try:
        with_socket.request("GET", route, headers={"Accept": "application/json"})
        with with_socket.getresponse() as response:
            if response.status != 200:
                raise AuditInputError("CONTROLLER_HTTP_ERROR")
            data = response.read(limit + 1)
    except (OSError, http.client.HTTPException):
        raise AuditInputError("CONTROLLER_UNREACHABLE") from None
    finally:
        with_socket.close()
    if len(data) > limit:
        raise AuditInputError("CONTROLLER_RESPONSE_TOO_LARGE")
    return parse_object(data)


def load_runtime(path, policy):
    try:
        info = path.lstat()
    except OSError:
        raise AuditInputError("SOCKET_UNAVAILABLE") from None
    if not path.is_absolute() or not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise AuditInputError("EXPECTED_OWNED_UNIX_SOCKET")
    return {
        "configs": socket_get(path, "/configs", MAX_POLICY),
        "rules": socket_get(path, "/rules", MAX_RUNTIME),
        "group": socket_get(path, "/proxies/" + quote(policy["group"], safe=""), MAX_POLICY),
        "node": socket_get(path, "/proxies/" + quote(policy["node"], safe=""), MAX_POLICY),
    }


def evaluate(policy, runtime):
    if any(not isinstance(runtime.get(key), dict) for key in ("configs", "rules", "group", "node")):
        raise AuditInputError("INVALID_RUNTIME_SHAPE")
    configs, rules, group, node = (runtime[key] for key in ("configs", "rules", "group", "node"))
    actual_rules = rules.get("rules")
    if not isinstance(actual_rules, list):
        raise AuditInputError("INVALID_RUNTIME_RULES")

    failures = []

    def fail(code, position=None):
        result = {"code": code}
        if position is not None:
            result["position"] = position
        failures.append(result)

    if configs.get("mode") != "rule":
        fail("MODE_MISMATCH")
    tun = configs.get("tun")
    if not isinstance(tun, dict) or tun.get("enable") is not policy["tun"]:
        fail("TUN_MISMATCH")
    if (any(rule_type(rule["type"]).startswith("process") for rule in policy["rules"])
            and configs.get("find-process-mode") not in ("strict", "always")):
        fail("PROCESS_MATCHING_UNAVAILABLE")
    if group.get("name") != policy["group"]:
        fail("GROUP_MISMATCH")
    if group.get("all") != [policy["node"]]:
        fail("GROUP_MEMBERS_MISMATCH")
    if group.get("now") != policy["node"]:
        fail("SELECTED_NODE_MISMATCH")
    if node.get("name") != policy["node"] or "all" in node or not rule_type(node.get("type")):
        fail("NODE_NOT_CONFIRMED_LEAF")
    elif rule_type(node.get("type")) in NON_PROXY_TYPES:
        fail("NODE_NOT_PROXY")
    if node.get("dialer-proxy") not in (None, ""):
        fail("NODE_USES_DIALER_PROXY")

    for index, expected in enumerate(policy["rules"]):
        position = index + 1
        if index >= len(actual_rules):
            fail("RULE_MISSING", position)
            continue
        actual = actual_rules[index]
        if (not isinstance(actual, dict) or rule_type(actual.get("type")) != rule_type(expected["type"])
                or actual.get("payload") != expected["payload"] or actual.get("proxy") != policy["group"]):
            fail("RULE_MISMATCH", position)
            continue
        extra = actual.get("extra")
        disabled = extra.get("disabled") if isinstance(extra, dict) else None
        if disabled is True:
            fail("RULE_DISABLED", position)
        elif disabled is not False:
            fail("RULE_STATE_UNKNOWN", position)
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"Mihomo Route Audit {VERSION}")
    parser.add_argument("--policy", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", type=Path, help="absolute path to an existing user-owned Unix socket")
    source.add_argument("--snapshot", type=Path, help="offline JSON with configs, rules, group and node")
    args = parser.parse_args(argv)
    mode = "snapshot" if args.snapshot else "live"
    try:
        policy = read_object(args.policy, MAX_POLICY)
        validate_policy(policy)
        runtime = read_object(args.snapshot, MAX_RUNTIME) if args.snapshot else load_runtime(args.socket, policy)
        failures = evaluate(policy, runtime)
    except AuditInputError as error:
        print(json.dumps({"status": "ERROR", "mode": mode, "code": str(error)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "FAIL" if failures else "PASS", "mode": mode,
                      "rules_checked": len(policy["rules"]), "failures": failures}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
