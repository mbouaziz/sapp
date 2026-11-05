# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast, IO

from ..analysis_output import AnalysisOutput
from ..models import HANDLE_LENGTH
from . import (
    ParseError,
    ParseIssueConditionTuple,
    ParseIssueLeaf,
    ParseIssueTuple,
    SourceLocation,
)
from .base_parser import BaseParser


# Rules without a code in rule-codes.json import under this generic code.
TS_LOCAL_FLOW_WARNING_CODE: int = 20002
# SAPP reads these markers in leaf kinds as taint transforms.
_KIND_TRANSFORM_MARKERS: tuple[str, ...] = ("->", "@", "!")


class LocalFlowParserError(ParseError):
    pass


@dataclass(frozen=True)
class _Endpoint:
    callable: str
    file: str


@dataclass(frozen=True)
class _Location:
    file: str
    line: int


@dataclass(frozen=True)
class _IssueFacts:
    location_source: _Location
    location_target: _Location
    sink_call: _Location | None
    path: tuple[str, ...]
    source_kinds: tuple[str, ...] = ()
    sink_kinds: tuple[str, ...] = ()
    features: tuple[str, ...] = ()
    # Call chains, and paths below the reached root, that reach the same target
    # share a canonical flow.
    call_chains: int = 1
    sink_call_sites: int = 1
    paths: int = 1


@dataclass(frozen=True)
class _ParsedFlow:
    canonical_id: str
    issues: list[ParseIssueTuple]
    payload: bytes


def _decode_object(value: str, context: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise LocalFlowParserError(f"invalid {context}: {error}") from error

    if not isinstance(decoded, dict):
        raise LocalFlowParserError(f"{context} must be a JSON object")
    return decoded


def _require_fields(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise LocalFlowParserError(
            f"invalid {context} fields: expected {sorted(expected)}, "
            f"got {sorted(value)}"
        )


def _parse_nonempty_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise LocalFlowParserError(f"{context} must be a nonempty string")
    return value


def _parse_optional_string(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _parse_nonempty_string(value, context)


def _parse_endpoint(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LocalFlowParserError(f"{context} must be an object")
    _require_fields(value, {"callable", "file"}, context)
    callable_name = _parse_nonempty_string(value["callable"], f"{context}.callable")
    # Endpoints that models define have an empty file.
    filename = value["file"]
    if not isinstance(filename, str):
        raise LocalFlowParserError(f"{context}.file must be a string")

    return {"callable": callable_name, "file": filename}


def _parse_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LocalFlowParserError("canonical flow must be an object")

    _require_fields(
        value,
        {
            "source",
            "target",
            "seed_port",
            "reached_root",
            "source_callee",
            "target_caller",
        },
        "canonical flow",
    )
    # LFE writes the fields in this order, and the ID hashes that encoding.
    return {
        "source": _parse_endpoint(value["source"], "canonical flow source"),
        "target": _parse_endpoint(value["target"], "canonical flow target"),
        "seed_port": _parse_optional_string(
            value["seed_port"], "canonical flow seed_port"
        ),
        "reached_root": _parse_optional_string(
            value["reached_root"], "canonical flow reached_root"
        ),
        "source_callee": _parse_nonempty_string(
            value["source_callee"], "canonical flow source_callee"
        ),
        "target_caller": _parse_nonempty_string(
            value["target_caller"], "canonical flow target_caller"
        ),
    }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _validate_identity(canonical_id: str, identity_json: str) -> dict[str, object]:
    identity = _parse_identity(_decode_object(identity_json, "canonical flow identity"))
    canonical_json = _canonical_json(identity)
    if identity_json != canonical_json:
        raise LocalFlowParserError(
            "canonical flow must use the canonical JSON encoding"
        )

    expected_id = hashlib.sha256(canonical_json.encode()).hexdigest()
    if canonical_id != expected_id:
        raise LocalFlowParserError(
            f"canonical flow ID `{canonical_id}` does not match its identity"
        )

    return identity


def _validate_payload(payload: dict[str, Any]) -> bool:
    """Validates the trace envelope and returns whether the trace is available."""
    status = payload.get("trace_status")
    if status == "available":
        if not isinstance(payload.get("title"), str) or not isinstance(
            payload.get("description"), str
        ):
            raise LocalFlowParserError("trace title and description must be strings")
        if not isinstance(payload.get("patrace"), dict):
            raise LocalFlowParserError("patrace must be an object")
        if not isinstance(payload.get("semantic_trace"), dict):
            raise LocalFlowParserError("semantic_trace must be an object")
        return True
    if status == "trace_unavailable":
        reason = payload.get("reason")
        if not isinstance(reason, dict):
            raise LocalFlowParserError("trace-unavailable reason must be an object")
        if not isinstance(reason.get("reason"), str) or not isinstance(
            reason.get("limit"), str
        ):
            raise LocalFlowParserError(
                "trace-unavailable reason and limit must be strings"
            )
        return False
    raise LocalFlowParserError(f"unsupported trace status `{status}`")


def _parse_strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise LocalFlowParserError(f"{context} must be nonempty strings")
    return tuple(cast(list[str], value))


def _parse_kinds(value: object, context: str) -> tuple[str, ...]:
    kinds = _parse_strings(value, context)
    if any(marker in kind for kind in kinds for marker in _KIND_TRANSFORM_MARKERS):
        raise LocalFlowParserError(f"{context} must not use SAPP transform syntax")
    return kinds


def _rule_name(rule: str) -> str:
    # Bundle rules are `<query identifier>|<output>`; the identifier is a stem
    # for app runners and a path for runners with a query root.
    query_identifier = rule.split("|", 1)[0]
    name = query_identifier.rsplit("/", 1)[-1].removesuffix(".lf")
    return name or rule


def _rule_names(rules: Iterable[str]) -> list[str]:
    return sorted({_rule_name(rule) for rule in rules})


def _parse_count(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LocalFlowParserError(f"{context} must be a positive integer")
    return value


def _merge_suffix(facts: _IssueFacts) -> str:
    if facts.call_chains == 1:
        return ""
    sites = facts.sink_call_sites
    chains = facts.call_chains
    return (
        f" ({sites} call site{'s' if sites != 1 else ''}, "
        f"{chains} call chain{'s' if chains != 1 else ''})"
    )


def _parse_location(value: object, context: str) -> _Location:
    if not isinstance(value, dict):
        raise LocalFlowParserError(f"{context} must be an object")
    _require_fields(value, {"file", "line"}, context)
    filename = value["file"]
    line = value["line"]
    # LFE cannot place constants or nodes that several records share; they have
    # an empty file and line 0.
    if not isinstance(filename, str):
        raise LocalFlowParserError(f"{context}.file must be a string")
    if not isinstance(line, int) or isinstance(line, bool) or line < 0:
        raise LocalFlowParserError(f"{context}.line must be a non-negative integer")
    return _Location(file=filename, line=line)


def _parse_issue_facts(payload: dict[str, Any]) -> _IssueFacts:
    # Every payload places its flow; other facts default when absent, and fields
    # that later LFE versions add are ignored.
    facts = payload.get("issue_facts")
    if not isinstance(facts, dict):
        raise LocalFlowParserError("issue_facts must be an object")
    location = facts.get("location")
    if not isinstance(location, dict):
        raise LocalFlowParserError("issue_facts.location must be an object")
    _require_fields(
        location, {"source", "target", "sink_call", "path"}, "issue_facts.location"
    )
    sink_call = location["sink_call"]
    path = location["path"]
    if not isinstance(path, list) or not all(isinstance(label, str) for label in path):
        raise LocalFlowParserError("issue_facts.location.path must be a string list")
    return _IssueFacts(
        location_source=_parse_location(
            location["source"], "issue_facts.location.source"
        ),
        location_target=_parse_location(
            location["target"], "issue_facts.location.target"
        ),
        sink_call=None
        if sink_call is None
        else _parse_location(sink_call, "issue_facts.location.sink_call"),
        path=tuple(cast(list[str], path)),
        source_kinds=_parse_kinds(
            facts.get("source_kinds", []), "issue_facts.source_kinds"
        ),
        sink_kinds=_parse_kinds(facts.get("sink_kinds", []), "issue_facts.sink_kinds"),
        features=_parse_strings(facts.get("features", []), "issue_facts.features"),
        call_chains=_parse_count(
            facts.get("call_chains", 1), "issue_facts.call_chains"
        ),
        sink_call_sites=_parse_count(
            facts.get("sink_call_sites", 1), "issue_facts.sink_call_sites"
        ),
        paths=_parse_count(facts.get("paths", 1), "issue_facts.paths"),
    )


def _endpoint(identity: dict[str, object], name: str) -> _Endpoint:
    endpoint = cast(dict[str, object], identity[name])
    return _Endpoint(
        callable=cast(str, endpoint["callable"]),
        file=cast(str, endpoint["file"]),
    )


def _validate_rule_mapping(
    flows_to_rules: Mapping[str, Iterable[str]],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for flow_id, rule_values in flows_to_rules.items():
        if isinstance(rule_values, str):
            raise LocalFlowParserError(
                "flows-to-rules must map IDs to unique nonempty rule names"
            )
        rules = list(rule_values)
        if (
            not rules
            or any(not isinstance(rule, str) or not rule for rule in rules)
            or len(set(rules)) != len(rules)
        ):
            raise LocalFlowParserError(
                "flows-to-rules must map IDs to unique nonempty rule names"
            )
        result[flow_id] = sorted(rules)

    return result


class LocalFlowParser(BaseParser):
    def __init__(
        self,
        repository: str,
        project: str,
    ) -> None:
        super().__init__()
        if not repository or not project:
            raise LocalFlowParserError("repository and project must be nonempty")
        self.repository = repository
        self.project = project
        self.flows_to_rules: dict[str, list[str]] = {}
        self.rule_codes: dict[str, int] = {}
        self.handles_to_keep: set[str] | None = None
        self.trace_payloads_by_handle: dict[str, bytes] = {}

    def set_handles_to_keep(self, handles_to_keep: AbstractSet[str]) -> None:
        self.handles_to_keep = set(handles_to_keep)

    def parse(self, input: AnalysisOutput) -> Iterable[ParseIssueTuple]:
        self.trace_payloads_by_handle.clear()
        directory = _results_directory(input)
        self.flows_to_rules = _load_flows_to_rules(directory)
        self.rule_codes = _load_rule_codes(directory)
        yield from self._parse_handles(input.file_handles())

    def _parse_handles(self, handles: Iterable[IO[str]]) -> Iterable[ParseIssueTuple]:
        seen: set[str] = set()
        payloads: dict[str, bytes] = {}

        for handle in handles:
            for line_number, row in enumerate(handle, 1):
                flow = self._parse_row(row.removesuffix("\n"), line_number)
                if flow.canonical_id in seen:
                    raise LocalFlowParserError(
                        f"duplicate canonical ID `{flow.canonical_id}`"
                    )
                seen.add(flow.canonical_id)
                for issue in flow.issues:
                    if (
                        self.handles_to_keep is not None
                        and issue.handle not in self.handles_to_keep
                    ):
                        continue
                    payloads[issue.handle] = flow.payload
                    yield issue

        if seen != set(self.flows_to_rules):
            raise LocalFlowParserError(
                "canonical rows and flows-to-rules do not exactly match"
            )

        if self.handles_to_keep is not None:
            missing = self.handles_to_keep - set(payloads)
            if missing:
                raise LocalFlowParserError(
                    "requested issue handles are absent from the local-flow result: "
                    f"{sorted(missing)}"
                )

        self.trace_payloads_by_handle.update(payloads)

    def _parse_row(self, row: str, line_number: int) -> _ParsedFlow:
        # LFE export_canonical emits headerless TSV rows:
        # SHA-256 flow ID, canonical identity JSON, and trace payload JSON.
        # Sandcastle also reads these rows for combination and diff analysis;
        # this adapter converts them into SAPP issues and retains payload bytes.
        fields = row.split("\t")
        if len(fields) != 3 or not fields[0]:
            raise LocalFlowParserError(
                f"row {line_number} must contain exactly three tab-separated fields"
            )

        canonical_id, identity_json, payload_json = fields
        identity = _validate_identity(canonical_id, identity_json)
        payload = _decode_object(payload_json, "canonical trace payload")
        trace_available = _validate_payload(payload)
        facts = _parse_issue_facts(payload)
        rules = self.flows_to_rules.get(canonical_id)

        if rules is None:
            raise LocalFlowParserError(
                "canonical rows and flows-to-rules do not exactly match"
            )

        rules_by_code: dict[int, list[str]] = {}
        for rule in rules:
            code = self.rule_codes.get(rule, TS_LOCAL_FLOW_WARNING_CODE)
            rules_by_code.setdefault(code, []).append(rule)
        shared_features = [
            *facts.features,
            "local-flow-trace:available"
            if trace_available
            else "local-flow-trace:unavailable",
        ]
        source = _endpoint(identity, "source")
        target = _endpoint(identity, "target")
        # The issue sits at the call site next to the sink, or at the target's
        # record when the flow crosses no call. Locations have no columns.
        issue_location = facts.sink_call or facts.location_target
        location = SourceLocation(
            line_no=issue_location.line, begin_column=1, end_column=1
        )
        preconditions = _leaf_frames(
            target.callable, "sink", facts.sink_kinds, location
        )
        postconditions = _leaf_frames(
            source.callable, "source", facts.source_kinds, location
        )
        initial_sources = _issue_leaves(source.callable, facts.source_kinds)
        final_sinks = _issue_leaves(target.callable, facts.sink_kinds)

        return _ParsedFlow(
            canonical_id=canonical_id,
            payload=payload_json.encode(),
            issues=[
                ParseIssueTuple(
                    code=code,
                    message=(
                        f"Local flow from {source.callable} to {target.callable}"
                        f"{_merge_suffix(facts)}"
                    ),
                    callable=target.callable,
                    handle=self._issue_handle(code, canonical_id),
                    filename=issue_location.file,
                    line=issue_location.line,
                    start=location.begin_column,
                    end=location.end_column,
                    preconditions=preconditions,
                    postconditions=postconditions,
                    initial_sources=initial_sources,
                    final_sinks=final_sinks,
                    features=[
                        f"local-flow-rule:{name}" for name in _rule_names(code_rules)
                    ]
                    + shared_features,
                    callable_line=issue_location.line,
                    fix_info=None,
                )
                for code, code_rules in sorted(rules_by_code.items())
            ],
        )

    def _issue_handle(self, code: int, canonical_id: str) -> str:
        handle = (
            f"ts-local-flow:{self.repository}:{self.project}:v3:{code}:{canonical_id}"
        )
        if len(handle) > HANDLE_LENGTH:
            raise LocalFlowParserError(
                f"issue handle `{handle}` exceeds {HANDLE_LENGTH} characters"
            )
        return handle


def _leaf_frames(
    callee: str, port: str, kinds: tuple[str, ...], location: SourceLocation
) -> list[ParseIssueConditionTuple]:
    # SAPP derives an issue's Source and Sink kinds only from the leaves of its
    # trace frames, so each classified endpoint becomes one leaf frame at the
    # issue location.
    if not kinds:
        return []
    return [
        ParseIssueConditionTuple(
            callee=callee,
            port=port,
            location=location,
            leaves=[(kind, 0) for kind in kinds],
            titos=[],
            features=[],
            type_interval=None,
            annotations=[],
        )
    ]


def _issue_leaves(endpoint: str, kinds: tuple[str, ...]) -> list[ParseIssueLeaf]:
    # SAPP shows these callables as the issue's source and sink names, so an
    # endpoint without kinds still contributes its name.
    return [(endpoint, kind, 0) for kind in kinds or ("",)]


def _results_directory(input: AnalysisOutput) -> Path:
    if input.directory is None:
        raise LocalFlowParserError("TS Local Flow import requires a results directory")
    return Path(input.directory)


def _load_flows_to_rules(directory: Path) -> dict[str, list[str]]:
    path = directory / "flows-to-rules.json"
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise LocalFlowParserError(
            f"cannot read flows-to-rules file `{path}`"
        ) from error
    return _validate_rule_mapping(_decode_flows_to_rules(contents))


def _load_rule_codes(directory: Path) -> dict[str, int]:
    path = directory / "rule-codes.json"
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Bundles written before rules declared codes have no rule-codes file.
        return {}
    except (OSError, UnicodeError) as error:
        raise LocalFlowParserError(f"cannot read rule-codes file `{path}`") from error

    rule_codes = _decode_object(contents, "rule-codes")
    for rule, code in rule_codes.items():
        if not isinstance(code, int) or isinstance(code, bool):
            raise LocalFlowParserError(f"rule `{rule}` must map to an integer code")
    return cast(dict[str, int], rule_codes)


def _decode_flows_to_rules(contents: str) -> dict[str, list[str]]:
    decoded = _decode_object(contents, "flows-to-rules")

    result: dict[str, list[str]] = {}
    for flow_id, rules in decoded.items():
        if not isinstance(rules, list) or any(
            not isinstance(rule, str) for rule in rules
        ):
            raise LocalFlowParserError(
                f"rules for canonical ID `{flow_id}` must be a string list"
            )
        result[flow_id] = rules

    return result
