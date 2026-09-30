"""하드닝 점검 — BPFDoor 같은 커널 단 백도어가 동작할 조건(닿기 · 설치 · 유출)을 미리 막았는지 본다.

① 매직 패킷이 닿지 않게: 외부 직접 노출(0.0.0.0 바인딩, host 네트워크, 공개 포트)
② 설치할 권한이 없게: root 실행, NET_RAW · BPF · SYS_ADMIN 권한, systemd 샌드박스 지시어
③ 코드 자체가 raw/packet 소켓이나 BPF 필터를 쓰는지 (백도어 흔적 또는 불필요한 위험)
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Edit, Finding, Fix, read_lines
from ..walk import iter_files

DANGER_CAPS = ("ALL", "NET_RAW", "NET_ADMIN", "SYS_ADMIN", "BPF", "SYS_MODULE", "SYS_PTRACE")
SYSTEMD_REQUIRED = {
    "NoNewPrivileges": "NoNewPrivileges=yes",
    "RestrictAddressFamilies": "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "SystemCallFilter": "SystemCallFilter=@system-service\nSystemCallFilter=~bpf",
    "CapabilityBoundingSet": "CapabilityBoundingSet=",
    "ProtectKernelModules": "ProtectKernelModules=yes",
}
RAW_SOCKET_RX = re.compile(r"AF_PACKET|SOCK_RAW|SO_ATTACH_FILTER|SO_ATTACH_BPF|\bbpf\s*\(|BPF\.|from bcc import")
BIND_ALL_RX = re.compile(r"""(host\s*=\s*["']0\.0\.0\.0["']|--host[ =]0\.0\.0\.0|-b\s*0\.0\.0\.0|--bind[ =]0\.0\.0\.0)""")
PORT_RX = re.compile(r"""^\s*-\s*["']?(\d+):(\d+)""")


def _dockerfile(service: str, path: Path, rel: str) -> list[Finding]:
    lines = read_lines(path)
    if any(re.match(r"\s*USER\s+(?!root\b|0\b)\S", ln, re.I) for ln in lines):
        return []
    last_from = max((i for i, ln in enumerate(lines, 1) if re.match(r"\s*FROM\b", ln, re.I)), default=1)
    return [Finding(service, "hardening", "HARD-DOCKER-ROOT", "high", "컨테이너가 root 로 실행", rel, last_from,
                    "USER 지시어가 없어 root 로 돕니다. 서비스가 뚫리면 raw 소켓 · BPF 필터를 걸 수 있어 "
                    "BPFDoor 같은 백도어 설치가 쉬워집니다. 전용 계정을 만들고 USER 로 전환하세요.",
                    lines[last_from - 1].strip()[:200] if lines else "",
                    Fix("수동 조치: RUN useradd -r app && USER app 추가"))]


def _compose(service: str, path: Path, rel: str) -> list[Finding]:
    lines = read_lines(path)
    out: list[Finding] = []

    def add(i, rule, sev, title, detail, fix="수동 조치"):
        out.append(Finding(service, "hardening", rule, sev, title, rel, i, detail, lines[i - 1].strip()[:200], Fix(fix)))

    in_ports = False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if re.match(r"privileged:\s*true", s):
            add(i, "HARD-PRIVILEGED", "critical", "privileged 컨테이너",
                "호스트 커널 권한을 통째로 줍니다. 커널 모듈 · BPF 설치가 가능합니다.", "수동 조치: privileged 제거")
        if re.match(r"network_mode:\s*[\"']?host", s):
            add(i, "HARD-HOST-NET", "high", "host 네트워크 사용",
                "호스트로 오는 모든 패킷이 컨테이너에 닿습니다. 매직 패킷 차단이 어려워집니다.",
                "수동 조치: 브리지 네트워크 + 프록시 뒤로")
        caps = [c for c in DANGER_CAPS if re.search(rf"\b(CAP_)?{c}\b", s)] if "cap_add" in s or s.startswith("- ") else []
        if caps and any("cap_add" in lines[j] for j in range(max(0, i - 6), i)):
            add(i, "HARD-CAP-ADD", "high", f"위험 권한 추가: {', '.join(caps)}",
                "raw 소켓 · BPF · 커널 조작 권한입니다. 서비스에 꼭 필요한지 확인하세요.", "수동 조치: cap_add 제거")
        if re.match(r"ports:\s*$", s):
            in_ports = True
            continue
        if in_ports:
            m = PORT_RX.match(ln)
            if m:
                add(i, "HARD-PORT-PUBLIC", "medium", f"포트 {m.group(1)} 이 모든 인터페이스에 공개",
                    "호스트 IP 없이 공개하면 외부에서 직접 닿습니다. 프록시만 받게 127.0.0.1:포트:포트 로 묶으세요.",
                    f"수동 조치: \"127.0.0.1:{m.group(1)}:{m.group(2)}\"")
            elif s and not s.startswith("-"):
                in_ports = False
    text = "\n".join(lines)
    if re.search(r"^\s*(image|build):", text, re.M) and "no-new-privileges" not in text:
        add(1, "HARD-NO-NEW-PRIV", "medium", "no-new-privileges 미설정",
            "security_opt: [\"no-new-privileges:true\"] 가 없으면 setuid 로 권한 상승이 가능합니다.",
            "수동 조치: security_opt 추가, cap_drop: [ALL]")
    return out


def _systemd(service: str, path: Path, rel: str) -> list[Finding]:
    lines = read_lines(path)
    sec = next((i for i, ln in enumerate(lines, 1) if ln.strip() == "[Service]"), None)
    if sec is None:
        return []
    out: list[Finding] = []
    user = next((ln.split("=", 1)[1].strip() for ln in lines if ln.strip().startswith("User=")), "")
    if user in ("", "root", "0"):
        out.append(Finding(service, "hardening", "HARD-SYSTEMD-ROOT", "high", "systemd 서비스가 root 로 실행", rel, sec,
                           "User= 가 없거나 root 입니다. 전용 계정으로 돌려야 raw 소켓 · BPF 를 못 씁니다.",
                           "[Service]", Fix("수동 조치: 전용 계정 생성 후 User= 지정")))
    keys = {ln.split("=", 1)[0].strip() for ln in lines if "=" in ln}
    missing = [k for k in SYSTEMD_REQUIRED if k not in keys]
    if missing:
        add = "\n".join(SYSTEMD_REQUIRED[k] for k in missing)
        out.append(Finding(service, "hardening", "HARD-SYSTEMD-SANDBOX", "medium",
                           f"systemd 샌드박스 지시어 {len(missing)}개 없음", rel, sec,
                           "AF_PACKET 소켓 · bpf() 시스템콜 · 커널 모듈 로드를 막는 지시어가 없습니다: " + ", ".join(missing),
                           "[Service]", Fix("샌드박스 지시어 추가", [Edit(rel, sec, lines[sec - 1], lines[sec - 1] + "\n" + add)])))
    return out


def _code(service: str, path: Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for i, ln in enumerate(read_lines(path), 1):
        s = ln.strip()
        if s.startswith("#"):
            continue
        if RAW_SOCKET_RX.search(s):
            out.append(Finding(service, "hardening", "HARD-RAW-SOCKET", "critical", "raw/packet 소켓 · BPF 사용 코드",
                               rel, i, "BPFDoor 류 백도어가 쓰는 방식입니다. 웹 서비스에는 필요 없는 기능이라 "
                               "의도한 코드인지 사람이 확인해야 합니다.", s[:200], Fix("수동 조치: 출처 확인 후 제거")))
        elif BIND_ALL_RX.search(s):
            out.append(Finding(service, "hardening", "HARD-BIND-ALL", "medium", "모든 인터페이스(0.0.0.0)에 바인딩",
                               rel, i, "외부에서 서비스 포트에 직접 닿습니다. 프록시 뒤에 두고 127.0.0.1 로 받으세요 "
                               "(컨테이너 안이라면 포트 공개 쪽에서 제한).", s[:200], Fix("수동 조치: HOST 환경변수로 제어")))
    return out


def scan(service: str, root: Path) -> list[Finding]:
    out: list[Finding] = []
    deploy = False
    for path, rel in iter_files(root):
        name = path.name.lower()
        if name == "dockerfile" or name.endswith(".dockerfile"):
            deploy = True
            out += _dockerfile(service, path, rel)
        elif re.match(r"(docker-)?compose.*\.ya?ml$", name):
            deploy = True
            out += _compose(service, path, rel)
        elif name.endswith(".service"):
            deploy = True
            out += _systemd(service, path, rel)
        elif path.suffix.lower() in (".py", ".sh", ".ps1", ".bat", ".cmd") or name == "procfile":
            out += _code(service, path, rel)
    if not deploy:
        out.append(Finding(service, "hardening", "HARD-NO-DEPLOY", "low", "배포 하드닝 설정 없음", "", 0,
                           "Dockerfile · compose · systemd 유닛이 없어 실행 권한 · 네트워크 제한을 확인할 수 없습니다. "
                           "배포 방식이 정해지면 root 금지 · cap_drop ALL · 프록시 뒤 배치 · 나가는 연결 허용 목록을 함께 넣으세요.",
                           "", Fix("수동 조치: 배포 설정 작성 시 하드닝 포함")))
    return out
