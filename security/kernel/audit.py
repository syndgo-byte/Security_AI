"""Read-only kernel version, sysctl and module audit."""
from __future__ import annotations

import re

from ..findings import Finding, Fix
from .host import BLACKLIST, MODPROBE_CONF, SERVICE, TARGETS, USERNS_KEY, Host, _unsupported

# Introduced version, mainline fix, and stable branch fixes.
CVES = {
    "CVE-2022-0847": ("Dirty Pipe", (5, 8, 0), (5, 16, 11), {(5, 10): 102, (5, 15): 25, (5, 16): 11}),
    "CVE-2024-1086": ("netfilter nf_tables UAF", (3, 15, 0), (6, 8, 0),
                      {(5, 4): 269, (5, 10): 209, (5, 15): 149, (6, 1): 76, (6, 6): 15, (6, 7): 3}),
}


def _ver(s: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def _exposed(v, introduced, mainline, branches) -> bool:
    if v < introduced or v >= mainline:
        return False
    fix = branches.get(v[:2])
    return not (fix is not None and v[2] >= fix)


def audit(h: Host) -> dict:
    if not h.supported:
        return _unsupported()
    kver = h.kernel()
    v = _ver(kver)
    cont = h.containers()
    out: list[Finding] = []
    for cve, (name, intro, main, br) in CVES.items():
        if v and _exposed(v, intro, main, br):
            out.append(Finding(SERVICE, "kernel", f"KERN-{cve}", "high", f"{name} ({cve}) 노출 가능 — 배포판 백포트 확인 필요",
                               "proc/sys/kernel/osrelease", 0, f"커널 {kver} 는 업스트림 기준 취약 범위입니다. "
                               "배포판이 패치를 백포트했는지 확인하고 커널을 업데이트하세요.", kver, Fix("수동 조치: 커널 업데이트")))
    if v and v >= (5, 1, 0) and h.sysctl("kernel.io_uring_disabled") is None:
        out.append(Finding(SERVICE, "kernel", "KERN-IOURING-NOSWITCH", "medium", "io_uring 끄는 sysctl 없음", "", 0,
                           "6.6 미만 커널이라 kernel.io_uring_disabled 가 없습니다. seccomp 로 io_uring_setup 을 막거나 커널을 올리세요.",
                           kver, Fix("수동 조치: seccomp / 커널 업데이트")))
    for key, (want, sev, title, detail) in TARGETS.items():
        cur = h.sysctl(key)
        if cur is None or cur == want:
            continue
        if key == USERNS_KEY and cont:
            out.append(Finding(SERVICE, "kernel", "KERN-USERNS-CONTAINER", "low", "user namespace 허용 (컨테이너 사용 중이라 유지)",
                               "", 0, f"컨테이너 런타임 감지({', '.join(cont)}) — 차단하면 rootless 컨테이너가 깨질 수 있어 제외합니다.",
                               f"{key} = {cur}", Fix("harden --block-userns 로 강제 가능")))
            continue
        out.append(Finding(SERVICE, "kernel", "KERN-SYSCTL-" + key.split(".")[-1].upper(), sev, title,
                           "proc/sys/" + key.replace(".", "/"), 0, detail + f" 권장 {key} = {want}",
                           f"{key} = {cur}", Fix("harden 으로 적용")))
    loaded, black = set(h.modules()), h.blacklisted()
    for mod in BLACKLIST:
        if mod in black:
            continue
        if mod in loaded:
            out.append(Finding(SERVICE, "kernel", "KERN-MOD-LOADED", "medium", f"위험 모듈 {mod} 로드됨", "proc/modules", 0,
                               "사용 중인 모듈이라 자동 차단하지 않습니다. 쓰는 곳이 없으면 언로드 후 블랙리스트하세요.",
                               mod, Fix("수동 조치: 사용처 확인 후 modprobe -r")))
        else:
            out.append(Finding(SERVICE, "kernel", "KERN-MOD-BLACKLIST", "low", f"미사용 위험 모듈 {mod} 미차단", MODPROBE_CONF, 0,
                               "자동 로드로 공격면이 열릴 수 있습니다.", mod, Fix("harden 으로 블랙리스트")))
    return {"supported": True, "kernel": kver, "os": h.os_release().get("PRETTY_NAME", ""), "containers": cont,
            "findings": [f.to_dict() for f in out]}
