from app.need_engine import (
    InventoryItem, evaluate_need, relevance, effective_type,
    Relevance, Verdict, NEED_RULES,
)

NEED = "shirt_pants_formal_shoes"


def I(aid, at, st=None, cond="good", arch=None):
    return InventoryItem(aid, at, {"sub_type": st} if st else {}, cond, arch)


def full():
    return [I("1", "shirt"), I("2", "pants"), I("3", "formal_shoes")]


def test_full_match():
    r = evaluate_need(NEED, full())
    assert r.status == "EVALUATE" and r.has_sufficient_items is True and r.gaps == []


def test_fair_is_not_accepted_without_rule():
    inv = [I("1", "shirt", cond="fair"), I("2", "pants"), I("3", "formal_shoes")]
    r = evaluate_need(NEED, inv)
    assert r.status == "ABSTAIN" and r.reason_code == "AMBIGUOUS_DATA"
    assert r.unknown_requirements == ["shirt"]


def test_unknown_condition_abstains():
    r = evaluate_need(NEED, [I("1", "shirt", cond="unknown")])
    assert r.reason_code == "AMBIGUOUS_DATA" and r.has_sufficient_items is None


def test_broken_is_gap():
    inv = [I("1", "shirt", cond="broken"), I("2", "pants"), I("3", "formal_shoes")]
    assert evaluate_need(NEED, inv).gaps == ["shirt"]


def test_poor_is_gap():
    inv = [I("1", "shirt", cond="poor"), I("2", "pants"), I("3", "formal_shoes")]
    assert evaluate_need(NEED, inv).gaps == ["shirt"]


def test_archived_not_counted():
    inv = [I("1", "shirt", arch="2020-01-01"), I("2", "pants"), I("3", "formal_shoes")]
    r = evaluate_need(NEED, inv)
    assert r.gaps == ["shirt"] and "1" not in r.matched_items


def test_unknown_subtype_is_unknown():
    r = evaluate_need(NEED, [I("1", "garment", "blouse")])
    assert r.reason_code == "AMBIGUOUS_DATA"


def test_irrelevant_known_type_with_unknown_condition_does_not_abstain():
    inv = [I("9", "garment", "dress", cond="unknown")] + full()
    r = evaluate_need(NEED, inv)
    assert r.status == "EVALUATE" and r.has_sufficient_items is True


def test_subtype_conflict_is_unknown():
    r = evaluate_need(NEED, [I("1", "shirt", "pants")])
    assert r.reason_code == "AMBIGUOUS_DATA"


def test_incompatible_broad_pair_is_unknown():
    r = evaluate_need(NEED, [I("1", "footwear", "shirt")])
    assert r.reason_code == "AMBIGUOUS_DATA"


def test_broad_without_subtype_is_unknown():
    r = evaluate_need(NEED, [I("1", "shoes")])
    assert r.reason_code == "AMBIGUOUS_DATA"


def test_known_dress_is_definite_non_match():
    inv = [I("1", "garment", "dress"), I("2", "pants"), I("3", "formal_shoes")]
    assert evaluate_need(NEED, inv).gaps == ["shirt"]


def test_declared_out_of_domain_is_insufficient():
    assert evaluate_need(NEED, [I("1", "book")]).reason_code == "INSUFFICIENT_INVENTORY_DATA"


def test_empty_inventory():
    assert evaluate_need(NEED, []).reason_code == "INSUFFICIENT_INVENTORY_DATA"


def test_unsupported_checked_before_inventory():
    assert evaluate_need("fly_to_mars", []).reason_code == "UNSUPPORTED_NEED_TYPE"


def test_no_reuse_single_item(monkeypatch):
    monkeypatch.setitem(NEED_RULES, "two_shirts",
                        {"requirements": ["shirt", "shirt"], "acceptable_conditions": {"new", "good"}})
    r = evaluate_need("two_shirts", [I("1", "shirt")])
    assert r.has_sufficient_items is False and r.gaps == ["shirt"]


def test_arabic_alias():
    assert evaluate_need("قميص_بنطال_حذاء_رسمي", full()).has_sufficient_items is True


def test_uninterpretable_pair_is_not_silently_dropped():
    r = evaluate_need(NEED, [I("1", "misc", "blouse")])
    assert r.status == "ABSTAIN" and r.reason_code == "UNCLASSIFIABLE_INVENTORY"
    assert r.has_sufficient_items is None


def test_definite_full_match_wins_over_unclassifiable():
    r = evaluate_need(NEED, full() + [I("9", "misc", "blouse")])
    assert r.status == "EVALUATE" and r.has_sufficient_items is True


def test_gap_not_asserted_while_unclassifiable_exists():
    inv = [I("1", "shirt"), I("2", "pants"), I("9", "misc", "blouse")]
    r = evaluate_need(NEED, inv)
    assert r.status == "ABSTAIN" and r.reason_code == "UNCLASSIFIABLE_INVENTORY"
    assert r.gaps == [] and r.unknown_requirements == ["formal_shoes"]


def test_gap_asserted_when_nothing_unclassifiable():
    r = evaluate_need(NEED, [I("1", "shirt"), I("2", "pants")])
    assert r.status == "EVALUATE" and r.gaps == ["formal_shoes"]


def test_unknown_subtype_on_declared_out_of_domain_is_unknown():
    r = evaluate_need(NEED, [I("1", "book", "blouse")])
    assert r.status == "ABSTAIN"
    assert r.reason_code == "UNCLASSIFIABLE_INVENTORY"


def test_archived_unclassifiable_item_does_not_block_gap():
    inv = [
        I("1", "shirt"),
        I("2", "pants"),
        I("9", "misc", "blouse", arch="2026-01-01"),
    ]
    r = evaluate_need(NEED, inv)
    assert r.status == "EVALUATE"
    assert r.has_sufficient_items is False
    assert r.gaps == ["formal_shoes"]


def test_non_string_subtype_is_unclassifiable():
    item = InventoryItem(
        item_id="1",
        asset_type="misc",
        attributes={"sub_type": {"category": "blouse"}},
    )
    r = evaluate_need(NEED, [item])
    assert r.status == "ABSTAIN"
    assert r.reason_code == "UNCLASSIFIABLE_INVENTORY"


def test_non_string_subtype_list_is_unclassifiable():
    item = InventoryItem(item_id="1", asset_type="garment",
                         attributes={"sub_type": ["shirt"]})
    r = evaluate_need(NEED, [item])
    assert r.status == "ABSTAIN"


def test_non_object_attributes_is_tolerated():
    item = InventoryItem(item_id="1", asset_type="shirt", attributes=["not", "a", "dict"])
    r = evaluate_need(NEED, [item, I("2", "pants"), I("3", "formal_shoes")])
    assert r.status == "EVALUATE" and r.has_sufficient_items is True


# ── Regression locks: a known asset_type must never be erased by an
#    unrecognised sub_type. Relevance stays RELEVANT; ambiguity is local. ──
def test_known_asset_type_with_unknown_subtype_stays_relevant():
    item = I("1", "shirt", "blouse")
    assert relevance(item) is Relevance.RELEVANT
    assert effective_type(item) is None
    r = evaluate_need(NEED, [item])
    assert r.status == "ABSTAIN"
    assert r.reason_code == "AMBIGUOUS_DATA"          # NOT UNCLASSIFIABLE_INVENTORY
    assert r.unknown_requirements == ["shirt"]


def test_unknown_subtype_does_not_erase_other_matched_evidence():
    inv = [I("1", "shirt", "blouse"), I("2", "pants"), I("3", "formal_shoes")]
    r = evaluate_need(NEED, inv)
    assert r.reason_code == "AMBIGUOUS_DATA"
    assert set(r.matched_items) == {"2", "3"}
    assert r.unknown_requirements == ["shirt"]
    assert r.gaps == []
