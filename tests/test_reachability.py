"""Reachability unit tests — no network. Exercises prompt construction, sink
resolution (qualname matching, suffix fallback), and Flow coercion.
"""

from __future__ import annotations

from pathlib import Path

from conftest import FakeLLM

from arbiter.llm.reachability import (
    REACH_SCHEMA,
    REACH_SYSTEM,
    REACH_TOOLS,
    analyze_reachability,
    filter_sinks_by_imports,
)
from arbiter.models import AttackerModel, Exposure, Flow, Sink, SinkFamily, Target


def _target() -> Target:
    return Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression.",
        exposure=Exposure.library,
    )


def _sinks() -> list[Sink]:
    return [
        Sink(
            family=SinkFamily.code_exec,
            callable_qualname="eval",
            file="vulnpkg/api.py",
            line=14,
        ),
        Sink(
            family=SinkFamily.deserialization,
            callable_qualname="yaml.unsafe_load",
            file="vulnpkg/api.py",
            line=18,
        ),
        Sink(
            family=SinkFamily.template,
            callable_qualname="jinja2.Environment",
            file="vulnpkg/api.py",
            line=24,
        ),
    ]


def test_analyze_reachability_returns_flow_list():
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval",
                    "intermediate": [],
                    "confidence": 0.95,
                    "rationale": "direct call eval(expr)",
                }
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert isinstance(flows[0], Flow)
    assert flows[0].sink.callable_qualname == "eval"
    assert flows[0].confidence == 0.95
    assert flows[0].target_fqn == "vulnpkg.api:eval_expression"


def test_analyze_reachability_passes_agent_mode_flags():
    fake = FakeLLM(response={"flows": []})
    analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)

    call = fake.last
    assert call["tools"] == REACH_TOOLS
    assert call["add_dirs"] == ["/tmp/pkg"]
    assert call["system_mode"] == "append"
    assert call["schema"] is REACH_SCHEMA
    assert call["system"][0].text == REACH_SYSTEM


def test_analyze_reachability_resolves_sink_via_suffix():
    """Model returns 'unsafe_load' instead of 'yaml.unsafe_load'."""
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "unsafe_load", "confidence": 0.8, "intermediate": []}
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].sink.callable_qualname == "yaml.unsafe_load"


def test_analyze_reachability_strips_at_location_suffix():
    """Model occasionally parrots 'qualname at file.py:LN' format from the
    prompt; the resolver must strip the suffix to match the bare qualname."""
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "yaml.unsafe_load at vulnpkg/api.py:18",
                    "confidence": 0.9,
                    "intermediate": [],
                },
                {
                    "sink_qualname": "eval at vulnpkg/api.py:14",
                    "confidence": 0.7,
                    "intermediate": [],
                },
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 2
    quals = sorted(f.sink.callable_qualname for f in flows)
    assert quals == ["eval", "yaml.unsafe_load"]


def test_analyze_reachability_strips_in_module_suffix():
    """Some prompt regressions surface as 'X in module.py'."""
    fake = FakeLLM(
        response={
            "flows": [{"sink_qualname": "eval in api.py", "confidence": 0.8, "intermediate": []}]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].sink.callable_qualname == "eval"


def test_analyze_reachability_carries_harness_target_through():
    """When the LLM emits harness_module/harness_qualname, they land on the Flow."""
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval",
                    "intermediate": ["cmd_editor", "pipe_editor"],
                    "confidence": 0.9,
                    "rationale": "argv -> cmd_editor -> pipe_editor -> eval",
                    "harness_module": "vulnpkg.editor",
                    "harness_qualname": "pipe_editor",
                }
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].harness_module == "vulnpkg.editor"
    assert flows[0].harness_qualname == "pipe_editor"


def test_analyze_reachability_drops_partial_harness():
    """If only one of harness_module/harness_qualname is present, drop both —
    a half-specified harness is useless."""
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval",
                    "confidence": 0.9,
                    "harness_module": "vulnpkg.editor",
                    # harness_qualname omitted
                }
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].harness_module is None
    assert flows[0].harness_qualname is None


def test_analyze_reachability_omitting_harness_keeps_entry():
    """Default case — no harness fields means we'll fuzz the entry target."""
    fake = FakeLLM(
        response={
            "flows": [{"sink_qualname": "eval", "confidence": 0.9, "intermediate": []}]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].harness_module is None
    assert flows[0].harness_qualname is None


def test_analyze_reachability_strips_paren_at_form():
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval (at api.py:14)",
                    "confidence": 0.6,
                    "intermediate": [],
                }
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].sink.callable_qualname == "eval"


def test_analyze_reachability_drops_unknown_sink():
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "nonexistent.fn", "confidence": 0.9, "intermediate": []},
                {"sink_qualname": "eval", "confidence": 0.5, "intermediate": []},
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].sink.callable_qualname == "eval"


def test_analyze_reachability_clamps_confidence():
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "eval", "confidence": 1.5, "intermediate": []},
                {"sink_qualname": "yaml.unsafe_load", "confidence": -0.2, "intermediate": []},
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    confidences = {f.sink.callable_qualname: f.confidence for f in flows}
    assert confidences["eval"] == 1.0
    assert confidences["yaml.unsafe_load"] == 0.0


def test_analyze_reachability_sorts_by_confidence_descending():
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "eval", "confidence": 0.3, "intermediate": []},
                {"sink_qualname": "yaml.unsafe_load", "confidence": 0.9, "intermediate": []},
                {"sink_qualname": "jinja2.Environment", "confidence": 0.6, "intermediate": []},
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    confidences = [f.confidence for f in flows]
    assert confidences == sorted(confidences, reverse=True)


def test_analyze_reachability_short_circuits_when_no_sinks():
    fake = FakeLLM(response={"flows": []})
    flows = analyze_reachability(_target(), [], Path("/tmp/pkg"), llm=fake)
    assert flows == []
    assert fake.calls == []  # no LLM call made when there are no sinks


def test_analyze_reachability_includes_sink_inventory_in_user_prompt():
    fake = FakeLLM(response={"flows": []})
    analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    user = fake.last["user"]
    assert "eval" in user
    assert "yaml.unsafe_load" in user
    assert "jinja2.Environment" in user
    assert "vulnpkg.api:eval_expression" in user or "eval_expression" in user


# --- filter_sinks_by_imports ---


def _write_pkg(root: Path, layout: dict[str, str]) -> Path:
    if "__init__.py" not in layout:
        layout = {"__init__.py": "", **layout}
    for rel, src in layout.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src)
    return root


def _make_target(module: str) -> Target:
    return Target(
        module=module,
        qualname="entry",
        signature="(x: str) -> None",
        exposure=Exposure.network,
    )


def _make_sink(file: Path) -> Sink:
    return Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file=str(file),
        line=1,
    )


def test_filter_sinks_by_imports_ranks_in_closure_first(tmp_path):
    """Default behavior is rank-by-distance, not hard-drop. With max_sinks
    larger than the input, every sink survives but in-closure ones are ranked
    ahead of out-of-closure ones."""
    pkg = _write_pkg(
        tmp_path / "pkg",
        {
            "entry.py": "from pkg import helper",
            "helper.py": "v = 1",
            "untouched.py": "v = 2",
        },
    )
    sinks = [
        _make_sink(pkg / "untouched.py"),
        _make_sink(pkg / "entry.py"),
        _make_sink(pkg / "helper.py"),
    ]
    ranked = filter_sinks_by_imports(_make_target("pkg.entry"), sinks, pkg, "pkg")
    names = [Path(s.file).name for s in ranked]
    # entry.py (distance 0) and helper.py (distance 1) come first; untouched is last.
    assert names[-1] == "untouched.py"
    assert set(names[:2]) == {"entry.py", "helper.py"}


def test_filter_sinks_by_imports_caps_at_max_sinks(tmp_path):
    """When the input exceeds max_sinks, drop the most distant first."""
    pkg = _write_pkg(
        tmp_path / "pkg",
        {
            "entry.py": "from pkg import a",
            "a.py": "v = 1",
            "far.py": "v = 2",
        },
    )
    sinks = [
        _make_sink(pkg / "far.py"),       # out of closure
        _make_sink(pkg / "entry.py"),     # distance 0
        _make_sink(pkg / "a.py"),         # distance 1
    ]
    kept = filter_sinks_by_imports(_make_target("pkg.entry"), sinks, pkg, "pkg", max_sinks=2)
    names = {Path(s.file).name for s in kept}
    assert names == {"entry.py", "a.py"}, f"out-of-closure sink should be dropped first; got {names}"


def test_filter_sinks_by_imports_falls_back_when_target_unknown(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"entry.py": ""})
    sinks = [_make_sink(pkg / "entry.py")]
    # target.module isn't inside the package — closure returns None.
    filtered = filter_sinks_by_imports(
        _make_target("not_pkg.entry"), sinks, pkg, "pkg"
    )
    assert filtered == sinks


def test_filter_sinks_by_imports_keeps_out_of_closure_sinks_under_cap(tmp_path):
    """Out-of-closure sinks are ranked last but still kept when the cap allows."""
    pkg = _write_pkg(tmp_path / "pkg", {"entry.py": "v = 1"})
    sinks = [_make_sink(tmp_path / "outside.py")]
    ranked = filter_sinks_by_imports(_make_target("pkg.entry"), sinks, pkg, "pkg")
    assert ranked == sinks  # cap (15) > 1, so the single sink survives


def test_analyze_reachability_inherits_attacker_model_from_target():
    """When the LLM omits attacker_model, the Flow inherits the target's
    effective model."""
    target = Target(
        module="p.m",
        qualname="handle",
        signature="(req)",
        exposure=Exposure.network,
    )
    fake = FakeLLM(
        response={"flows": [{"sink_qualname": "eval", "confidence": 0.9}]}
    )
    sinks = [Sink(family=SinkFamily.code_exec, callable_qualname="eval", file="p/m.py", line=1)]
    flows = analyze_reachability(target, sinks, Path("/tmp/pkg"), llm=fake)
    assert flows[0].attacker_model is AttackerModel.network


def test_analyze_reachability_accepts_per_flow_attacker_model_override():
    """A network entry that opens a file should be allowed to refine its
    flow's attacker_model to loaded_file_content."""
    target = Target(
        module="p.m",
        qualname="open_file",
        signature="(path: str)",
        exposure=Exposure.network,
    )
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval",
                    "confidence": 0.9,
                    "attacker_model": "loaded_file_content",
                }
            ]
        }
    )
    sinks = [Sink(family=SinkFamily.code_exec, callable_qualname="eval", file="p/m.py", line=1)]
    flows = analyze_reachability(target, sinks, Path("/tmp/pkg"), llm=fake)
    assert flows[0].attacker_model is AttackerModel.loaded_file_content


def test_analyze_reachability_drops_unknown_attacker_model_and_inherits():
    target = Target(
        module="p.m",
        qualname="handle",
        signature="(req)",
        exposure=Exposure.cli,
    )
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval",
                    "confidence": 0.9,
                    "attacker_model": "definitely_not_a_thing",
                }
            ]
        }
    )
    sinks = [Sink(family=SinkFamily.code_exec, callable_qualname="eval", file="p/m.py", line=1)]
    flows = analyze_reachability(target, sinks, Path("/tmp/pkg"), llm=fake)
    # Falls through to target's default for cli → argv
    assert flows[0].attacker_model is AttackerModel.argv


def test_analyze_reachability_user_prompt_shows_target_attacker_model():
    target = Target(
        module="p.m",
        qualname="open_file",
        signature="(path: str)",
        exposure=Exposure.network,
        attacker_model=AttackerModel.loaded_file_content,
    )
    fake = FakeLLM(response={"flows": []})
    sinks = [Sink(family=SinkFamily.code_exec, callable_qualname="eval", file="p/m.py", line=1)]
    analyze_reachability(target, sinks, Path("/tmp/pkg"), llm=fake)
    assert "loaded_file_content" in fake.last["user"]


def test_filter_sinks_by_imports_includes_target_file_itself(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"entry.py": "v = 1"})
    sink_in_target = _make_sink(pkg / "entry.py")
    filtered = filter_sinks_by_imports(
        _make_target("pkg.entry"), [sink_in_target], pkg, "pkg"
    )
    assert filtered == [sink_in_target]
