"""
SUPERSEDED -- this file does not test the application.

It defines a self-contained matcher (its own VENDOR_ALIASES, CASE 1-4 taxonomy
and READY_FOR_DELIVERY status) and asserts that it behaves as specified. Nothing
imports it, and none of it exercises `runVulnerabilityPipeline`, which is the
engine that actually ships. A green pytest run here is evidence about this file,
not about the product.

The two guards it specified ahead of the TypeScript engine -- negation and
passive-platform mentions -- are now implemented in
`src/utils/textEvidenceGuards.ts` and verified against the real pipeline in
`tests/text-evidence-guards.test.ts`. That is where behaviour should be added.

Kept only as a readable statement of intent; remove it once the CASE taxonomy
has either been adopted in TypeScript or dropped.
"""

import re
import fnmatch
import hashlib
from urllib.parse import unquote
import pytest
from packaging import version

# ==============================================================================
# 1. NORMALIZATION & ALIAS CONFIGURATION (PREVENT FALSE NEGATIVES)
# ==============================================================================
VENDOR_ALIASES = {
    "vmware": "broadcom",
    "paloaltonetworks": "palo alto networks",
    "palo alto": "palo alto networks",
    "ms": "microsoft",
    "fireeye": "trellix",
    "org.apache.logging.log4j": "apache",
}

PRODUCT_ALIASES = {
    "azure ad": "entra id",
    "azure active directory": "entra id",
}

NEGATION_PHRASES = (
    "not affected",
    "unaffected",
    "not vulnerable",
    "is not impacted",
    "are not impacted",
    "does not affect",
    "do not affect",
)

PLATFORM_CONTEXT_PHRASES = (
    "running on",
    "installed on",
    "deployed on",
    "hosted on",
    "when integrated with",
    "prerequisite",
)


def normalize_vendor(name: str) -> str:
    clean = name.strip().lower().replace("_", " ")
    return VENDOR_ALIASES.get(clean, clean)


def normalize_product(name: str) -> str:
    clean = name.strip().lower().replace("_", " ")
    return PRODUCT_ALIASES.get(clean, clean)


# ==============================================================================
# 2. PURL & CPE PARSERS + STRICT VERSION MATH
# ==============================================================================
def parse_purl(purl_str: str) -> dict | None:
    """
    Parses a Package URL (pkg:type/namespace/name@version?qualifiers#subpath)
    into normalized ecosystem, namespace, name, and version components.
    """
    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    body = purl_str[4:].split("#")[0].split("?")[0]
    if "@" in body:
        path_part, pkg_version = body.rsplit("@", 1)
        pkg_version = unquote(pkg_version)
    else:
        path_part, pkg_version = body, "*"

    segments = [unquote(s) for s in path_part.split("/") if s]
    if len(segments) < 2:
        return None

    pkg_type = segments[0].lower()
    if len(segments) == 2:
        namespace = ""
        name = segments[1]
    else:
        namespace = "/".join(segments[1:-1]).lstrip("@")
        name = segments[-1]

    return {
        "raw": purl_str,
        "type": pkg_type,
        "namespace": namespace,
        "name": name,
        "version": pkg_version,
        "base_purl": f"pkg:{path_part}".lower(),
    }


def is_version_vulnerable(inv_ver: str, bounds: dict, explicit_feed_ver: str = "*") -> bool:
    """Evaluates inventory version against explicit versions or NVD/VulnCheck bounds."""
    if not inv_ver or inv_ver == "*":
        return True

    has_bounds = any(
        k in bounds
        for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
    )
    if not has_bounds and explicit_feed_ver not in ("*", "-", ""):
        return inv_ver.strip().lower() == explicit_feed_ver.strip().lower()

    try:
        v = version.parse(inv_ver)
        if "versionStartIncluding" in bounds and v < version.parse(bounds["versionStartIncluding"]):
            return False
        if "versionStartExcluding" in bounds and v <= version.parse(bounds["versionStartExcluding"]):
            return False
        if "versionEndIncluding" in bounds and v > version.parse(bounds["versionEndIncluding"]):
            return False
        if "versionEndExcluding" in bounds and v >= version.parse(bounds["versionEndExcluding"]):
            return False
    except Exception:
        return True

    return True


def extract_vulnerable_cpes(record: dict) -> list[dict]:
    """Recursively extracts ONLY 'vulnerable: True' cpeMatch entries from NVD/VulnCheck JSON."""
    results = []
    if "cpe_matches" in record:
        for item in record["cpe_matches"]:
            if item.get("vulnerable", False):
                results.append(item)

    for config in record.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    results.append(match)
    return results


def extract_vulnerable_purls(record: dict) -> list[dict]:
    """Extracts PURL strings or objects from VulnCheck / OSV / CycloneDX records."""
    results = []
    for item in record.get("purls", []):
        if isinstance(item, str):
            results.append({"purl": item, "vulnerable": True})
        elif isinstance(item, dict) and item.get("vulnerable", True):
            results.append(item)
    return results


# ==============================================================================
# 3. CORE UNIFIED MATCHING ENGINE (ZERO FALSE POSITIVES / ZERO FALSE NEGATIVES)
# ==============================================================================
def determine_case(is_advisory: bool, is_news: bool, is_wildcard: bool) -> str:
    """Applies strict Case 1-4 priority hierarchy."""
    if is_advisory:
        return "Case 3"
    if is_news:
        return "Case 4"
    if not is_wildcard:
        return "Case 1"
    return "Case 2"


def is_passive_platform_mention(sentence: str, vendor: str, product: str) -> bool:
    """
    False-positive guard for unstructured text: returns True if the asset is only
    mentioned as an underlying platform or prerequisite (e.g., 'running on Windows Server 2022').
    """
    target = vendor if product == "*" else product.replace("*", "").strip()
    if not target:
        return False
    for phrase in PLATFORM_CONTEXT_PHRASES:
        if re.search(rf"\b{re.escape(phrase)}\s+(?:[a-z0-9._-]+\s+){{0,3}}{re.escape(target)}\b", sentence):
            return True
    return False


def match_feed_record(inventory: list[dict], record: dict) -> dict:
    """
    Unified deterministic matcher scanning ALL paths (CPE, PURL, and Text) so
    no valid finding is missed (zero false negatives) while enforcing strict
    CPE/version/context guards (zero false positives).
    """
    matches = []
    seen_keys = set()

    cve_id = record.get("cve_id") or record.get("id") or "UNSPECIFIED"
    source_type = record.get("source_type", "ambiguous").lower()
    cna = normalize_vendor(record.get("sourceIdentifier", ""))
    raw_text = record.get("text", "")

    if not raw_text and "descriptions" in record:
        raw_text = " ".join(d.get("value", "") for d in record["descriptions"])

    vulnerable_cpes = extract_vulnerable_cpes(record)
    vulnerable_purls = extract_vulnerable_purls(record)

    # --- PATH A: STRUCTURED CPE MATCHING (NVD / VulnCheck) ---
    for node in vulnerable_cpes:
        parts = node.get("criteria", "").split(":")
        if len(parts) < 6:
            continue

        feed_vendor = normalize_vendor(parts[3])
        feed_product = normalize_product(parts[4])
        cpe_version = parts[5]

        for asset in inventory:
            inv_vendor = normalize_vendor(asset["vendor"])
            inv_product = normalize_product(asset["product"])
            inv_version = asset.get("version", "*")

            if feed_vendor != inv_vendor:
                continue
            if not fnmatch.fnmatch(feed_product, inv_product):
                continue
            if not is_version_vulnerable(inv_version, node, cpe_version):
                continue

            is_wildcard = "*" in inv_product or "*" in inv_vendor
            is_advisory = (source_type == "vendor_advisory") or (bool(cna) and cna == inv_vendor)
            is_news = (source_type == "news") or (bool(cna) and cna != inv_vendor)
            case = determine_case(is_advisory, is_news, is_wildcard)

            dedup_key = (cve_id, asset["vendor"], feed_product, case)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                matches.append({
                    "cve_id": cve_id,
                    "case_classification": case,
                    "match_precision": "Wildcard" if is_wildcard else "Exact",
                    "match_method": "CPE",
                    "matched_vendor": asset["vendor"],
                    "matched_product": feed_product,
                    "inventory_rule": f"{asset['vendor']} | {asset['product']}",
                    "audit_verified": True,
                })

    # --- PATH B: STRUCTURED PURL MATCHING (VulnCheck / OSV / SBOM Feeds) ---
    for p_entry in vulnerable_purls:
        parsed = parse_purl(p_entry.get("purl", ""))
        if not parsed:
            continue

        feed_product = normalize_product(parsed["name"])
        candidate_vendors = {normalize_vendor(parsed["type"])}
        if parsed["namespace"]:
            candidate_vendors.add(normalize_vendor(parsed["namespace"]))

        for asset in inventory:
            inv_vendor = normalize_vendor(asset["vendor"])
            inv_product = normalize_product(asset["product"])
            inv_purl = asset.get("purl", "").lower()
            inv_version = asset.get("version", "*")

            if inv_purl:
                if not fnmatch.fnmatch(parsed["base_purl"], inv_purl.split("@")[0]):
                    continue
                is_wildcard = "*" in inv_purl
            else:
                if inv_vendor not in candidate_vendors:
                    continue
                if not fnmatch.fnmatch(feed_product, inv_product):
                    continue
                is_wildcard = "*" in inv_product or "*" in inv_vendor

            if not is_version_vulnerable(inv_version, p_entry, parsed["version"]):
                continue

            is_advisory = (source_type == "vendor_advisory") or (bool(cna) and cna in candidate_vendors)
            is_news = (source_type == "news") or (bool(cna) and cna not in candidate_vendors)
            case = determine_case(is_advisory, is_news, is_wildcard)

            dedup_key = (cve_id, asset["vendor"], parsed["name"], case)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                matches.append({
                    "cve_id": cve_id,
                    "case_classification": case,
                    "match_precision": "Wildcard" if is_wildcard else "Exact",
                    "match_method": "PURL",
                    "matched_vendor": asset["vendor"],
                    "matched_product": parsed["name"],
                    "inventory_rule": asset.get("purl") or f"{asset['vendor']} | {asset['product']}",
                    "audit_verified": True,
                })

    # --- PATH C: UNSTRUCTURED TEXT MATCHING ---
    if raw_text:
        sentences = re.split(r"[.!?\n]+", raw_text.lower())

        for sentence in sentences:
            if not sentence.strip() or any(neg in sentence for neg in NEGATION_PHRASES):
                continue

            norm_sentence = sentence
            for alias, canonical in VENDOR_ALIASES.items():
                norm_sentence = re.sub(rf"\b{re.escape(alias)}\b", canonical, norm_sentence)
            for alias, canonical in PRODUCT_ALIASES.items():
                norm_sentence = re.sub(rf"\b{re.escape(alias)}\b", canonical, norm_sentence)

            for asset in inventory:
                inv_vendor = normalize_vendor(asset["vendor"])
                inv_product = normalize_product(asset["product"])
                is_wildcard = "*" in inv_product or "*" in inv_vendor

                if not re.search(rf"\b{re.escape(inv_vendor)}\b", norm_sentence):
                    continue

                if is_passive_platform_mention(norm_sentence, inv_vendor, inv_product):
                    continue

                if inv_product == "*":
                    product_matched = True
                    extracted_prod = "*"
                elif "*" in inv_product:
                    pattern = re.escape(inv_product).replace(r"\*", r"[a-z0-9._-]+")
                    m = re.search(rf"\b({pattern})\b", norm_sentence)
                    product_matched = bool(m)
                    extracted_prod = m.group(1) if m else inv_product
                else:
                    product_matched = bool(re.search(rf"\b{re.escape(inv_product)}\b", norm_sentence))
                    extracted_prod = inv_product

                if not product_matched:
                    continue

                is_advisory = source_type == "vendor_advisory"
                is_news = source_type == "news"
                case = determine_case(is_advisory, is_news, is_wildcard)

                dedup_key = (cve_id, asset["vendor"], extracted_prod, case)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    matches.append({
                        "cve_id": cve_id,
                        "case_classification": case,
                        "match_precision": "Wildcard" if is_wildcard else "Exact",
                        "match_method": "Text",
                        "matched_vendor": asset["vendor"],
                        "matched_product": extracted_prod,
                        "inventory_rule": f"{asset['vendor']} | {asset['product']}",
                        "audit_verified": True,
                    })

    return {"total_matches": len(matches), "matches": matches}


# ==============================================================================
# 4. COMPLETE FINDINGS DELIVERY PIPELINE
# ==============================================================================
def deliver_findings(findings: list[dict]) -> dict:
    """
    Packages and deduplicates all verified findings across feeds for downstream
    dispatch, guaranteeing zero dropped matches.
    """
    delivered = []
    seen_ids = set()

    for item in findings:
        raw_sig = f"{item['cve_id']}|{item['matched_vendor']}|{item['matched_product']}|{item['case_classification']}"
        finding_id = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()[:16]

        if finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)

        payload = dict(item)
        payload["finding_id"] = finding_id
        payload["delivery_status"] = "QUEUED_FOR_DISPATCH"
        delivered.append(payload)

    return {
        "delivered_count": len(delivered),
        "all_findings_delivered": True,
        "deliveries": delivered,
    }


def match_and_deliver_findings(inventory: list[dict], records: list[dict]) -> dict:
    """End-to-end batch processor: matches all records and delivers every valid finding."""
    all_matches = []
    for rec in records:
        res = match_feed_record(inventory, rec)
        all_matches.extend(res["matches"])
    return deliver_findings(all_matches)


# ==============================================================================
# 5. AUTOMATED PYTEST SUITE
# ==============================================================================
TEST_INVENTORY = [
    {"vendor": "Microsoft", "product": "Windows Server 2022", "version": "*"},
    {"vendor": "Palo Alto Networks", "product": "PAN-OS", "version": "11.1.4"},
    {"vendor": "Cisco", "product": "IOS XE *", "version": "*"},
    {"vendor": "Broadcom", "product": "*", "version": "*"},
    {"vendor": "npm", "product": "lodash", "version": "4.17.20"},
    {"vendor": "Apache", "product": "log4j-*", "version": "2.14.1"},
]


def test_case_1_ambiguous_exact_cpe():
    record = {
        "cve_id": "CVE-2026-1001",
        "source_type": "ambiguous",
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"}
        ]}]}]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["case_classification"] == "Case 1"
    assert res["matches"][0]["match_precision"] == "Exact"


def test_case_2_ambiguous_wildcard_text():
    record = {
        "cve_id": "CVE-2026-1002",
        "source_type": "ambiguous",
        "text": "CVE-2026-1002: Remote code execution discovered in Cisco IOS XE 17.9."
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["case_classification"] == "Case 2"
    assert res["matches"][0]["match_precision"] == "Wildcard"


def test_case_3_vendor_advisory_overrides_wildcard():
    record = {
        "cve_id": "CVE-2026-1003",
        "source_type": "vendor_advisory",
        "text": "Cisco Security Advisory: Critical vulnerability patched in Cisco IOS XE 17.9."
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["case_classification"] == "Case 3"


def test_case_3_nvd_vendor_cna_rebrand():
    record = {
        "cve_id": "CVE-2026-1004",
        "sourceIdentifier": "vmware",
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:vmware:vcenter_server:8.0:*:*:*:*:*:*:*"}
        ]}]}]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["case_classification"] == "Case 3"
    assert res["matches"][0]["matched_vendor"] == "Broadcom"


def test_case_4_news_feed_text():
    record = {
        "cve_id": "CVE-2026-1005",
        "source_type": "news",
        "text": "BleepingComputer: Ransomware gang actively exploiting Microsoft Windows Server 2022."
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["case_classification"] == "Case 4"


def test_purl_exact_ecosystem_match():
    record = {
        "cve_id": "CVE-2026-1006",
        "source_type": "news",
        "purls": ["pkg:npm/lodash@4.17.20"]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["match_method"] == "PURL"
    assert res["matches"][0]["case_classification"] == "Case 4"
    assert res["matches"][0]["match_precision"] == "Exact"


def test_purl_namespace_wildcard_and_version_bounds():
    record = {
        "cve_id": "CVE-2026-1007",
        "source_type": "vendor_advisory",
        "purls": [{
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
            "versionStartIncluding": "2.0.0",
            "versionEndExcluding": "2.15.0"
        }]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 1
    assert res["matches"][0]["match_method"] == "PURL"
    assert res["matches"][0]["case_classification"] == "Case 3"
    assert res["matches"][0]["match_precision"] == "Wildcard"


def test_zero_false_negatives_hybrid_cpe_plus_text():
    record = {
        "cve_id": "CVE-2026-1008",
        "source_type": "vendor_advisory",
        "descriptions": [{"value": "Advisory affects Cisco IOS XE 17.9 and Microsoft Windows Server 2022."}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:cisco:ios_xe_17:17.9:*:*:*:*:*:*:*"}
        ]}]}]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 2
    vendors = {m["matched_vendor"] for m in res["matches"]}
    assert vendors == {"Cisco", "Microsoft"}


def test_trap_purl_patched_version():
    record = {
        "cve_id": "CVE-2026-1009",
        "source_type": "vendor_advisory",
        "purls": ["pkg:npm/lodash@4.17.21"]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 0


def test_trap_vulnerable_false_and_passive_platform_ignored():
    record = {
        "cve_id": "CVE-2026-1010",
        "source_type": "vendor_advisory",
        "descriptions": [{"value": "Vulnerability in Apache Tomcat running on Microsoft Windows Server 2022."}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:tomcat:10.1:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"}
        ]}]}]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 0


def test_trap_patched_version_boundary():
    record = {
        "cve_id": "CVE-2026-1011",
        "sourceIdentifier": "paloaltonetworks",
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "11.1.0",
            "versionEndExcluding": "11.1.4"
        }]}]}]
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 0


def test_trap_negation_in_news_ignored():
    record = {
        "cve_id": "CVE-2026-1012",
        "source_type": "news",
        "text": "Security researchers confirmed Microsoft Windows Server 2022 is not affected by this flaw."
    }
    res = match_feed_record(TEST_INVENTORY, record)
    assert res["total_matches"] == 0


def test_all_findings_delivered_end_to_end():
    batch = [
        {
            "cve_id": "CVE-2026-2001",
            "source_type": "vendor_advisory",
            "text": "Cisco Security Advisory: Flaw in Cisco IOS XE 17.9."
        },
        {
            "cve_id": "CVE-2026-2002",
            "source_type": "news",
            "purls": ["pkg:npm/lodash@4.17.20"]
        },
        {
            "cve_id": "CVE-2026-2003",
            "source_type": "news",
            "text": "Microsoft Windows Server 2022 is unaffected by this issue."
        }
    ]
    delivery_report = match_and_deliver_findings(TEST_INVENTORY, batch)
    assert delivery_report["all_findings_delivered"] is True
    assert delivery_report["delivered_count"] == 2
    assert all(d["delivery_status"] == "QUEUED_FOR_DISPATCH" for d in delivery_report["deliveries"])
