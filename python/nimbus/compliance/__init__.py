"""Compliance engine: framework packs, weakness-derived coverage, custom frameworks, audit evidence.

Modelled on Prowler's compliance mapping style: each framework is an inventory of controls and
findings map onto controls through (1) explicit ``finding.compliance[framework]`` lists coming
from the canonical catalog, (2) ``weakness_mappings`` (SOC 2 / ISO 27001 coverage derived from
the attack-graph weakness vocabulary) and (3) custom frameworks that select findings by
canonical id or weakness.
"""
from .engine import (  # noqa: F401
    ControlResult, Evidence, Framework, Report, RoadmapItem, build_report, frameworks, load_custom_framework,
    load_frameworks, resolve_key, weakness_mappings,
)
