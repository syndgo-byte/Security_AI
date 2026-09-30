from security.scanners import legal


def _scan(tmp_path, files):
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return {f.rule: f for f in legal.scan("svc", tmp_path)}


WEB = "from fastapi import FastAPI\napp = FastAPI()\n"


def test_web_without_audit_log_flagged_and_with_it_not(tmp_path):
    assert "LEGAL-LOG-NO-ACCESS-LOG" in _scan(tmp_path, {"app.py": WEB})
    assert "LEGAL-LOG-NO-ACCESS-LOG" not in _scan(tmp_path, {"app.py": WEB + "def audit_log(u): ...\n"})


def test_non_web_code_not_flagged_for_access_log(tmp_path):
    assert _scan(tmp_path, {"lib.py": "def f(): return 1\n"}) == {}


def test_retention_under_one_year(tmp_path):
    r = _scan(tmp_path, {"a.py": WEB + "audit = 1\nLOG_RETENTION_DAYS = 90\n"})
    assert "90일" in r["LEGAL-LOG-RETENTION"].title
    assert "LEGAL-LOG-RETENTION" not in _scan(tmp_path, {"a.py": WEB + "audit = 1\nLOG_RETENTION_DAYS = 730\n"})


def test_timed_rotation_backup_count(tmp_path):
    src = "import logging.handlers as h\nh.TimedRotatingFileHandler('a.log', when='D', backupCount=30)\n"
    assert "LEGAL-LOG-RETENTION" in _scan(tmp_path, {"a.py": src})
    src = src.replace("30", "400")
    assert "LEGAL-LOG-RETENTION" not in _scan(tmp_path, {"a.py": src})
    # 시간 단위 회전의 backupCount 는 일수가 아니므로 판단하지 않는다
    assert "LEGAL-LOG-RETENTION" not in _scan(tmp_path, {"a.py": src.replace("400", "30").replace("'D'", "'H'")})


def test_jwt_without_exp(tmp_path):
    bad = "import jwt\ntok = jwt.encode({'sub': 1}, 'k')\n"
    assert "LEGAL-SESSION-NO-EXPIRY" in _scan(tmp_path, {"a.py": bad})
    assert "LEGAL-SESSION-NO-EXPIRY" not in _scan(tmp_path, {"a.py": bad.replace("'sub': 1", "'sub': 1, 'exp': 9")})


def test_cookie_max_age(tmp_path):
    r = _scan(tmp_path, {"a.py": "resp.set_cookie('s', v, max_age=60 * 60 * 24 * 90)\n"})
    assert "90일" in r["LEGAL-SESSION-LONG"].title
    assert "LEGAL-SESSION-LONG" not in _scan(tmp_path, {"a.py": "resp.set_cookie('s', v, max_age=3600)\n"})


def test_admin_without_mfa(tmp_path):
    code = WEB + "@app.get('/admin/users')\ndef u(): ...\n"
    assert "LEGAL-NO-MFA" in _scan(tmp_path, {"a.py": code})
    assert "LEGAL-NO-MFA" not in _scan(tmp_path, {"a.py": code + "import pyotp\n"})


def test_password_storage(tmp_path):
    model = "password = Column(String)\n"
    assert "LEGAL-PASSWORD-PLAIN" in _scan(tmp_path, {"m.py": model})
    assert "LEGAL-PASSWORD-PLAIN" not in _scan(tmp_path, {"m.py": model + "import bcrypt\n"})
    r = _scan(tmp_path, {"m.py": "import hashlib\nh = hashlib.sha256(password.encode()).hexdigest()\n"})
    assert "sha256" in r["LEGAL-PASSWORD-FAST-HASH"].title


def test_test_dirs_ignored(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("password = Column(String)\n", encoding="utf-8")
    assert legal.scan("svc", tmp_path) == []


def test_password_min_length(tmp_path):
    assert "LEGAL-PASSWORD-MINLEN" in _scan(tmp_path, {"a.py": "PASSWORD_MIN_LENGTH = 6\n"})
    assert "LEGAL-PASSWORD-MINLEN" in _scan(tmp_path, {"a.py": "password: str = Field(..., min_length=4)\n"})
    assert "LEGAL-PASSWORD-MINLEN" not in _scan(tmp_path, {"a.py": "PASSWORD_MIN_LENGTH = 10\n"})


def test_login_lockout(tmp_path):
    code = WEB + "audit = 1\n@app.post('/login')\ndef login(): ...\n"
    assert "LEGAL-NO-LOGIN-LOCKOUT" in _scan(tmp_path, {"a.py": code})
    assert "LEGAL-NO-LOGIN-LOCKOUT" not in _scan(tmp_path, {"a.py": code + "failed_attempts = 0\n"})


def test_login_lockout_recognises_throttle_helpers(tmp_path):
    """EMSv3 실제 코드 형태: security.login_locked(throttle_key) — 오탐이었던 것."""
    code = WEB + "audit = 1\n@app.post('/login')\ndef login():\n    wait = security.login_locked(throttle_key)\n"
    assert "LEGAL-NO-LOGIN-LOCKOUT" not in _scan(tmp_path, {"a.py": code})
