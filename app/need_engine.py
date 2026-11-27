"""VESTIYA Need Engine — pure logic. No DB, no HTTP, no env, no I/O.

SCOPE: PILOT_TAXONOMY is a narrow classification dictionary for the pilot need
below. It is NOT a general asset taxonomy. Anything it cannot interpret yields
UNKNOWN, never a definite non-match and never an exception.

EVIDENCE SCOPE: "recorded_inventory_only" means the items recorded and visible
inside the caller's workspace. scope="all_assets" means all asset types within
that recorded workspace inventory — NOT all possessions the person owns in the
real world. Absence in this inventory is never proof of absence in reality.

RELEVANCE ORDER (deliberate, do not reorder):
  1. archived            -> IRRELEVANT
  2. non-string sub_type -> UNKNOWN
  3. known domain type   -> RELEVANT
  4. unknown sub_type    -> UNKNOWN
  5. declared out-domain -> IRRELEVANT
  6. otherwise           -> UNKNOWN

AMBIGUITY CONTAINMENT: when effective_type is uninterpretable, UNKNOWN is
confined to the requirements the item could plausibly satisfy (candidate_types).
A known base type is never erased, and ambiguity never spreads to requirements
that base type cannot possibly fulfil.

EMPTY-TAXONOMY SEMANTICS: candidate_types returns None when candidates cannot be
enumerated. An empty taxonomy branch (e.g. "accessory": set()) means "no subtypes
declared yet", NOT "proven impossible" — and this holds whether the supplied
sub_type is known or unknown. Inability to enumerate is UNKNOWN, never NO_MATCH.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNKNOWN = "UNKNOWN"


class Relevance(str, Enum):
    RELEVANT = "RELEVANT"
    IRRELEVANT = "IRRELEVANT"
    UNKNOWN = "UNKNOWN"


KNOWN_SUBTYPES = {"shirt", "pants", "formal_shoes", "dress"}
PILOT_TAXONOMY: dict[str, set[str]] = {
    "garment": {"shirt", "pants", "dress"},
    "apparel": {"shirt", "pants", "dress"},
    "clothing": {"shirt", "pants", "dress"},
    "footwear": {"formal_shoes"},
    "shoes": {"formal_shoes"},
    "accessory": set(),
}
RELEVANT_TYPES = KNOWN_SUBTYPES | set(PILOT_TAXONOMY)

OUT_OF_DOMAIN_TYPES = {
    "book", "appliance", "furniture", "tool", "vehicle",
    "document", "electronics", "food",
}

UNUSABLE_CONDITIONS = {"broken", "poor"}

NEED_RULES: dict[str, dict[str, Any]] = {
    "shirt_pants_formal_shoes": {
        "requirements": ["shirt", "pants", "formal_shoes"],
        "acceptable_conditions": {"new", "good"},
    },
}
NEED_ALIASES = {"قميص_بنطال_حذاء_رسمي": "shirt_pants_formal_shoes"}


@dataclass
class InventoryItem:
    item_id: str
    asset_type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    condition_state: str = "unknown"
    archived_at: Any = None


@dataclass
class Evaluation:
    status: str
    has_sufficient_items: bool | None
    matched_items: list[str]
    gaps: list[str]
    unknown_requirements: list[str]
    reason_code: str
    reasoning: str
    evidence_scope: str = "recorded_inventory_only"


def _attrs(item: InventoryItem) -> dict[str, Any]:
    """JSONB may hold a non-object value. Treat it as no attributes."""
    a = item.attributes
    return a if isinstance(a, dict) else {}


def relevance(item: InventoryItem) -> Relevance:
    if item.archived_at is not None:
        return Relevance.IRRELEVANT

    at = item.asset_type
    st = _attrs(item).get("sub_type")

    if st is not None and not isinstance(st, str):
        return Relevance.UNKNOWN

    if at in RELEVANT_TYPES or st in RELEVANT_TYPES:
        return Relevance.RELEVANT

    if st is not None and st not in KNOWN_SUBTYPES:
        return Relevance.UNKNOWN

    if at in OUT_OF_DOMAIN_TYPES:
        return Relevance.IRRELEVANT

    return Relevance.UNKNOWN


def effective_type(item: InventoryItem) -> str | None:
    at = item.asset_type
    st = _attrs(item).get("sub_type")
    if st is not None:
        if not isinstance(st, str) or st not in KNOWN_SUBTYPES:
            return None
        if at == st:
            return st
        if at in PILOT_TAXONOMY:
            return st if st in PILOT_TAXONOMY[at] else None
        return None
    return at if at in KNOWN_SUBTYPES else None


def candidate_types(item: InventoryItem) -> set[str] | None:
    """Requirements this item could plausibly satisfy.

    Returns a NON-EMPTY set when candidates are enumerable.
    Returns None when they are NOT enumerable: an undeclared taxonomy branch,
    or an uninterpretable base/sub_type pair. None means UNKNOWN, never
    an exclusion — regardless of whether the supplied sub_type is known.
    """
    at = item.asset_type
    st = _attrs(item).get("sub_type")
    st_known = isinstance(st, str) and st in KNOWN_SUBTYPES
    at_known = at in KNOWN_SUBTYPES
    at_broad = at in PILOT_TAXONOMY

    if at_known and st_known:
        return {at, st}
    if at_known:
        return {at}
    if at_broad and st_known:
        allowed = set(PILOT_TAXONOMY[at])
        return (allowed | {st}) if allowed else None
    if at_broad:
        allowed = set(PILOT_TAXONOMY[at])
        return allowed if allowed else None
    if st_known:
        return {st}
    return None


def classify(item: InventoryItem, requirement: str, acceptable: set[str]) -> Verdict:
    if item.archived_at is not None:
        return Verdict.NO_MATCH

    eff = effective_type(item)

    if eff is None:
        cands = candidate_types(item)
        if cands is None or requirement in cands:
            return Verdict.UNKNOWN
        return Verdict.NO_MATCH

    if eff != requirement:
        return Verdict.NO_MATCH
    if item.condition_state in UNUSABLE_CONDITIONS:
        return Verdict.NO_MATCH
    if item.condition_state in acceptable:
        return Verdict.MATCH
    return Verdict.UNKNOWN


def _abstain(code, reasoning, matched=None, gaps=None, unknowns=None) -> Evaluation:
    return Evaluation("ABSTAIN", None, matched or [], gaps or [], unknowns or [], code, reasoning)


def evaluate_need(need_type: str, inventory: list[InventoryItem]) -> Evaluation:
    key = NEED_ALIASES.get(need_type, need_type)
    rule = NEED_RULES.get(key)
    if rule is None:
        return _abstain("UNSUPPORTED_NEED_TYPE",
                        f"Need type '{need_type}' is not in the supported vocabulary.")

    relevant: list[InventoryItem] = []
    unclassifiable: list[InventoryItem] = []
    for item in inventory:
        r = relevance(item)
        if r is Relevance.RELEVANT:
            relevant.append(item)
        elif r is Relevance.UNKNOWN:
            unclassifiable.append(item)

    if not relevant and not unclassifiable:
        return _abstain("INSUFFICIENT_INVENTORY_DATA",
                        "No recorded items are relevant to this need's domain.")
    if not relevant:
        return _abstain("UNCLASSIFIABLE_INVENTORY",
                        "Recorded items exist but their classification cannot be interpreted; "
                        "relevance to this need is undetermined.")

    acceptable = rule["acceptable_conditions"]
    used: set[str] = set()
    matched: list[str] = []
    gaps: list[str] = []
    unknowns: list[str] = []

    for req in rule["requirements"]:
        hit = None
        saw_unknown = False
        for item in relevant:
            if item.item_id in used:
                continue
            v = classify(item, req, acceptable)
            if v is Verdict.MATCH:
                hit = item
                break
            if v is Verdict.UNKNOWN:
                saw_unknown = True
        if hit is not None:
            matched.append(hit.item_id)
            used.add(hit.item_id)
        elif saw_unknown:
            unknowns.append(req)
        else:
            gaps.append(req)

    if unknowns:
        return _abstain("AMBIGUOUS_DATA",
                        "Recorded evidence cannot determine: " + ", ".join(unknowns) + ".",
                        matched, gaps, unknowns)

    if not gaps:
        return Evaluation("EVALUATE", True, matched, [], [], "FULL_MATCH",
                          "All required items are recorded and usable.")

    if unclassifiable:
        return _abstain("UNCLASSIFIABLE_INVENTORY",
                        "Uninterpretable recorded items may satisfy: " + ", ".join(gaps) +
                        "; absence cannot be asserted.",
                        matched, [], gaps)

    return Evaluation("EVALUATE", False, matched, gaps, [], "PARTIAL_MATCH",
                      "Recorded inventory lacks usable items for: " + ", ".join(gaps) + ".")
