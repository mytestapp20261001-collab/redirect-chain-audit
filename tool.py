#!/usr/bin/env python3
"""Offline audit, Python 3.12+ standard library only. Never performs networking."""
import argparse
import json
import stat
import sys
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_ITEMS = 256
MAX_FINDINGS = 500

class InputError(ValueError):
    """Safe error containing only a fixed code, never supplied data."""

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")

def object_schema(value, allowed, required):
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise InputError("invalid_schema")

def integer(value, low, high):
    return type(value) is int and low <= value <= high

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_member")
        result[key] = value
    return result

def reject_constant(value):
    raise InputError("non_finite_json_number")

class Report:
    def __init__(self):
        self.findings, self.count = [], 0
    def add(self, code, **location):
        self.count += 1
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(dict(code=code, **location))
    def finish(self, **data):
        return {"tool": TOOL, "status": "fail" if self.count else "pass",
                "finding_count": self.count, "findings": self.findings,
                "findings_truncated": self.count > len(self.findings), **data}

def error_result(code):
    return {"tool": TOOL, "status": "error", "error": code}

def audit(data):
    """Audit a JSON-shaped dict; return deterministic JSON-compatible data."""
    try:
        return _audit(data)
    except InputError as exc:
        return error_result(str(exc))

def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--input", default="-", help="JSON file, or - for stdin (default)")
        args = parser.parse_args(argv)
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            path = Path(args.input)
            if not stat.S_ISREG(path.stat().st_mode):
                raise InputError("regular_file_required")
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputError("input_size_limit")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                              parse_constant=reject_constant)
        except (ValueError, RecursionError) as exc:
            if isinstance(exc, InputError):
                raise
            raise InputError("invalid_json") from None
        result = audit(data)
    except InputError as exc:
        result = error_result(str(exc))
    except (OSError, UnicodeError):
        result = error_result("unreadable_utf8_input")
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False))
    return {"pass": 0, "fail": 1, "error": 2}[result["status"]]

import ipaddress
import re
from urllib.parse import urlsplit

TOOL = "redirect-chain-audit"
MAX_URL = 8192
DEFAULT_PORTS = {"http": 80, "https": 443}

def inspect_url(value, index, report):
    """Return only safe authority fields; do not return supplied URL components."""
    item = {"index": index, "parsed": False}
    def add(code):
        report.add(code, index=index)
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch.isspace() for ch in value):
        add("whitespace_or_control")
    if "\\" in value:
        add("backslash_ambiguity")
    try:
        parts = urlsplit(value)
    except ValueError:
        add("url_parse_error")
        return item
    scheme = parts.scheme.lower()
    item.update(scheme=scheme if scheme in DEFAULT_PORTS else None, query_present="?" in value.split("#", 1)[0],
                fragment_present="#" in value,
                userinfo_present="@" in parts.netloc)
    if scheme not in DEFAULT_PORTS:
        add("unsupported_or_missing_scheme")
    if not parts.netloc:
        add("missing_authority")
        return item
    if "@" in parts.netloc:
        add("userinfo_present")
    if parts.netloc.count("@") > 1:
        add("multiple_at_ambiguity")
    authority = parts.netloc.rsplit("@", 1)[-1]
    if "%" in authority:
        add("percent_encoded_or_scoped_authority")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        add("invalid_host_or_port")
        return item
    if not host:
        add("missing_host")
        return item
    # Everything emitted below is rebuilt from validated ASCII host/port data.
    if host.endswith("."):
        add("trailing_dot_host")
    if any(ord(ch) > 127 for ch in host):
        add("unicode_idna_mapping")
    host_ascii, kind = None, None
    if authority.startswith("["):
        close = authority.find("]")
        suffix = authority[close + 1:]
        if close < 0 or (suffix and not suffix.startswith(":")):
            add("bracket_suffix_ambiguity")
            return item
        if "%" in host:
            add("ipv6_zone_not_supported")
            return item
        try:
            address = ipaddress.IPv6Address(host)
            host_ascii, kind = str(address), "ipv6"
        except ValueError:
            add("unsupported_ip_literal")
            return item
        port_text = suffix[1:] if suffix.startswith(":") else None
    else:
        if ":" in host or "[" in authority or "]" in authority:
            add("unbracketed_or_invalid_ip_literal")
            return item
        port_text = authority.rsplit(":", 1)[1] if ":" in authority else None
        try:
            address = ipaddress.IPv4Address(host)
            host_ascii, kind = str(address), "ipv4"
        except ValueError:
            try:
                candidate = host.encode("idna").decode("ascii").lower()
                bare = candidate[:-1] if candidate.endswith(".") else candidate
                labels = bare.split(".")
                if not 1 <= len(bare) <= 253 or any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels
                ):
                    raise ValueError
                for label in labels:
                    if label.startswith("xn--"):
                        if label.encode("ascii").decode("idna").encode("idna").decode("ascii") != label:
                            raise ValueError
                host_ascii, kind = candidate, "dns_name"
                if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]*)", labels[-1]):
                    add("numeric_host_ambiguity")
            except (UnicodeError, ValueError):
                add("invalid_dns_or_idna_host")
                return item
    if port_text == "":
        add("empty_port")
    if port_text and (not port_text.isascii() or not port_text.isdecimal()):
        add("invalid_host_or_port")
        return item
    if port_text and len(port_text) > 1 and port_text.startswith("0"):
        add("noncanonical_port")
    if port == 0:
        add("zero_port")
    effective = port if port is not None else DEFAULT_PORTS.get(scheme)
    item.update(parsed=True, host=host_ascii, host_kind=kind,
                explicit_port=port, effective_port=effective)
    if scheme in DEFAULT_PORTS:
        display = "[" + host_ascii + "]" if kind == "ipv6" else host_ascii
        item["origin"] = scheme + "://" + display + ":" + str(effective)
    return item


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
BLOCKING_CODES = {"whitespace_or_control", "backslash_ambiguity", "numeric_host_ambiguity",
                  "unsupported_or_missing_scheme", "percent_encoded_or_scoped_authority"}

def remove_dot_segments(path):
    """RFC 3986 section 5.2.4, preserving repeated slashes and trailing slash."""
    output = ""
    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
        elif path.startswith("/./"):
            path = path[2:]
        elif path == "/.":
            path = "/"
        elif path.startswith("/../"):
            path = path[3:]
            output = output.rpartition("/")[0]
        elif path == "/..":
            path = "/"
            output = output.rpartition("/")[0]
        elif path in (".", ".."):
            path = ""
        else:
            boundary = path.find("/", 1 if path.startswith("/") else 0)
            if boundary < 0:
                output += path
                path = ""
            else:
                output += path[:boundary]
                path = path[boundary:]
    return output

def query_marker(value):
    return "?" in value.split("#", 1)[0]

def reference(value):
    parts = urlsplit(value)
    return {"scheme": parts.scheme, "authority": parts.netloc, "path": parts.path,
            "query": parts.query, "fragment": parts.fragment,
            "query_present": query_marker(value), "fragment_present": "#" in value}

def compose(value):
    return (value["scheme"] + "://" + value["authority"] + value["path"] +
            ("?" + value["query"] if value["query_present"] else "") +
            ("#" + value["fragment"] if value["fragment_present"] else ""))

def resolve(base_value, location):
    """Resolve RFC 3986 references; preserve empty query and RFC 9110 fragment inheritance."""
    base, ref = reference(base_value), reference(location)
    if ref["scheme"]:
        target = dict(ref)
        target["path"] = remove_dot_segments(ref["path"])
    elif ref["authority"]:
        target = dict(ref, scheme=base["scheme"])
        target["path"] = remove_dot_segments(ref["path"])
    else:
        target = dict(ref, scheme=base["scheme"], authority=base["authority"])
        if not ref["path"]:
            target["path"] = base["path"]
            if not ref["query_present"]:
                target["query"], target["query_present"] = base["query"], base["query_present"]
        else:
            merged = ref["path"] if ref["path"].startswith("/") else (
                (base["path"].rsplit("/", 1)[0] + "/" if "/" in base["path"] else "/") + ref["path"])
            target["path"] = remove_dot_segments(merged)
    inherited = not ref["fragment_present"] and base["fragment_present"]
    if inherited:
        target["fragment"], target["fragment_present"] = base["fragment"], True
    return compose(target), inherited

def model_url(value, index, report):
    local = Report()
    item = inspect_url(value, index, local)
    for finding in local.findings:
        report.add(finding["code"], url_index=index)
    usable = (item["parsed"] and item["scheme"] in DEFAULT_PORTS and
              not any(f["code"] in BLOCKING_CODES for f in local.findings))
    if not usable:
        return item, None
    parts = urlsplit(value)
    key = (item["origin"], remove_dot_segments(parts.path or "/"),
           parts.query, query_marker(value))
    return item, key

def _audit(data):
    object_schema(data, {"start_url", "responses", "max_redirects"}, {"start_url", "responses"})
    start = data["start_url"]
    if not isinstance(start, str) or not 1 <= len(start) <= MAX_URL:
        raise InputError("invalid_start_url")
    responses = data["responses"]
    if not isinstance(responses, list) or not 1 <= len(responses) <= MAX_ITEMS:
        raise InputError("responses_count_limit")
    budget = data.get("max_redirects", 10)
    if not integer(budget, 0, MAX_ITEMS):
        raise InputError("invalid_redirect_budget")
    total = len(start)
    for response in responses:
        object_schema(response, {"status", "location"}, {"status"})
        if not integer(response["status"], 200, 599):
            raise InputError("invalid_response_status")
        if "location" in response:
            location = response["location"]
            if not isinstance(location, str) or len(location) > MAX_URL:
                raise InputError("invalid_location")
            total += len(location)
    if total > MAX_BYTES:
        raise InputError("url_content_limit")
    report = Report()
    current_item, key = model_url(start, 0, report)
    trace, visited = [], {}
    redirects, consumed, complete = 0, 0, False
    reason = "invalid_start_url"
    current = start
    if key is not None:
        visited[key] = 0
        reason = "trace_ends_on_redirect"
        for index, response in enumerate(responses):
            consumed += 1
            status = response["status"]
            step = {"response_index": index, "status": status,
                    "request_origin": current_item["origin"]}
            trace.append(step)
            if status not in REDIRECT_STATUSES:
                reason, complete = "terminal_response", True
                step["location_not_followed"] = "location" in response
                if status in (300, 305, 306):
                    report.add("unmodeled_redirect_status", response_index=index)
                if index != len(responses) - 1:
                    report.add("responses_after_terminal", response_index=index,
                               extra_count=len(responses) - index - 1)
                break
            if "location" not in response:
                report.add("missing_location", response_index=index)
                reason = "missing_location"
                break
            location = response["location"]
            if any(ord(ch) <= 32 or ord(ch) == 127 or ch.isspace() for ch in location) or "\\" in location:
                report.add("ambiguous_location_characters", response_index=index)
                reason = "invalid_redirect_target"
                break
            try:
                ref = reference(location)
                if ref["scheme"] and (ref["scheme"] not in DEFAULT_PORTS or not ref["authority"]):
                    report.add("unsupported_or_authorityless_location", response_index=index)
                    reason = "invalid_redirect_target"
                    break
                # An explicit // with no authority is invalid, not a relative path.
                if location.startswith("//") and not ref["authority"]:
                    report.add("missing_location_authority", response_index=index)
                    reason = "invalid_redirect_target"
                    break
                target, inherited = resolve(current, location)
            except ValueError:
                report.add("invalid_location_reference", response_index=index)
                reason = "invalid_redirect_target"
                break
            if len(target) > MAX_URL:
                report.add("resolved_url_size_limit", response_index=index)
                reason = "invalid_redirect_target"
                break
            target_item, target_key = model_url(target, index + 1, report)
            step.update(location_is_relative=not bool(ref["scheme"] or ref["authority"]),
                        fragment_inherited=inherited)
            if target_key is None:
                reason = "invalid_redirect_target"
                break
            redirects += 1
            step.update(target_origin=target_item["origin"],
                        target_query_present=query_marker(target))
            if target_item["origin"] != current_item["origin"]:
                report.add("cross_origin_redirect", response_index=index)
            if current_item["scheme"] == "https" and target_item["scheme"] == "http":
                report.add("https_downgrade", response_index=index)
            if redirects > budget:
                report.add("redirect_budget_exceeded", response_index=index, max_redirects=budget)
                reason = "redirect_budget_exceeded"
                break
            if target_key in visited:
                report.add("redirect_loop", response_index=index,
                           first_request_index=visited[target_key])
                reason = "redirect_loop"
                break
            visited[target_key] = index + 1
            current, current_item = target, target_item
        else:
            report.add("incomplete_trace", response_index=len(responses) - 1)
    return report.finish(start=current_item if not trace else {"origin": trace[0]["request_origin"]},
                         trace=trace, response_count=len(responses),
                         consumed_response_count=consumed, redirect_count=redirects,
                         max_redirects=budget, complete=complete, stopped_reason=reason,
                         parser_model="RFC3986-resolution+urllib.parse+stdlib-idna2003")

if __name__ == "__main__":
    raise SystemExit(main())
