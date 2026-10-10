"""Compliance engine: framework packs, weakness-derived coverage, custom frameworks, audit evidence.

Modelled on Prowler's compliance mapping style: each framework is an inventory of controls and
findings map onto controls through (1) explicit ``finding.compliance[framework]`` lists coming
from the canonical catalog, (2) ``weakness_mappings`` (SOC 2 / ISO 27001 coverage derived from
the attack-graph weakness vocabulary) and (3) custom frameworks that select findings by
canonical id or weakness, and (4) per-control ``checks`` lists (frameworks imported from Prowler):
a finding maps to a control when its canonical id is listed. The bundle
(``nimbus/frameworks/frameworks.yaml``) is generated from the Go loader by internal/compliance/gen.
"""
from .engine import (  # noqa: F401
    DEFAULT_FRAMEWORK_SET, ControlResult, Evidence, Framework, Report, RoadmapItem, build_report, framework_set, frameworks,
    load_custom_framework, load_frameworks, resolve_key, weakness_mappings,
)
from .evidence import EvidenceError, EvidencePackage, read_evidence  # noqa: F401,E402
