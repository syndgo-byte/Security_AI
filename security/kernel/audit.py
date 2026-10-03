"""Read-only kernel findings; release ranges are not vendor patch attestation."""
from pathlib import Path

from ..findings import Finding
from . import host


def finding(rule: str, severity: str, title: str, detail: str, evidence: str = "",
            file: str = "/proc/sys") -> Finding:
    return Finding("host", "kernel", "KERN-" + rule, severity, title, file, 0, detail, evidence)


def cve_findings(release: str) -> list[Finding]:
    version = host.parse_version(release)
    unknown = version is None or "-rc" in release
    pipe = nft = False
    if not unknown:
        pipe = (5, 8, 0) <= version < (5, 17, 0)
        for branch, patch in (((5, 10), 102), ((5, 15), 25), ((5, 16), 11)):
            if version[:2] == branch and version[2] >= patch:
                pipe = False
        # NVD upstream ranges, checked 2026-10-03. Vendor backports require verification.
        nft = any(start <= version < end for start, end in (
            ((3, 15, 0), (5, 15, 149)), ((5, 16, 0), (6, 1, 76)),
            ((6, 2, 0), (6, 6, 15)), ((6, 7, 0), (6, 7, 3))))
    out = []
    for cve, name, exposed, source in (
        ("CVE-2022-0847", "Dirty Pipe", pipe, "https://dirtypipe.cm4all.com/"),
        ("CVE-2024-1086", "nf_tables", nft, "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
    ):
        status = "unknown" if unknown else "potentially_exposed" if exposed else "outside_known_upstream_range"
        out.append(finding(cve, "high" if exposed else "info", f"{name}: {status}",
                           "Check the vendor kernel advisory and reboot after updates; release-only inference "
                           f"cannot attest vendor backports. {source}", release, "/proc/sys/kernel/osrelease"))
    return out


def scan(root: Path = Path("/"), *, allow_userns: bool = False) -> list[Finding]:
    snapshot = host.inspect(root)
    if snapshot["status"] == "unsupported":
        return []
    return _findings(snapshot, allow_userns)


def _findings(snapshot: dict, allow_userns: bool) -> list[Finding]:
    out = cve_findings(snapshot["kernel"])
    for key, wanted in host.TARGETS.items():
        actual = snapshot["sysctls"].get(key)
        rule = "SYSCTL-" + key.upper().replace(".", "-").replace("_", "-")
        file = "/proc/sys/" + key.replace(".", "/")
        if key == host.USERNS_KEY and (snapshot["runtimes"] or allow_userns):
            out.append(finding(rule, "info", "user namespaces: skipped",
                               "Container runtime detected or --allow-userns selected; leave unchanged.",
                               str(actual), file))
        elif actual is None:
            out.append(finding(rule, "info", f"{key}: unavailable (skipped)",
                               snapshot["unavailable"].get(key, "unavailable"), file=file))
        elif actual != wanted:
            out.append(finding(rule, "high" if key in (host.BPF_KEY, "kernel.io_uring_disabled") else "medium",
                               f"{key}: hardening required", f"Target {wanted}; current {actual}. "
                               "Exposure reduction does not replace vendor kernel patches.", actual, file))
    for module in host.MODULES:
        loaded = module in snapshot["modules"]
        blocked = module in snapshot["blacklisted_modules"]
        if loaded or not blocked:
            out.append(finding("MODULE-" + module.upper(), "medium" if loaded else "low",
                               f"{module}: {'loaded; manual review required' if loaded else 'not blacklisted'}",
                               "Loaded modules are never unloaded or added to the managed blacklist.",
                               f"loaded={loaded}, blacklisted={blocked}", "/proc/modules"))
    return out


def audit(root: Path = Path("/"), *, allow_userns: bool = False) -> dict:
    if result := host.unsupported():
        return result
    try:
        snapshot = host.inspect(root)
        return {"status": "ok", "host": snapshot,
                "findings": [f.to_dict() for f in _findings(snapshot, allow_userns)]}
    except host.ERRORS as exc:
        return {"status": "error", "message": str(exc)}
