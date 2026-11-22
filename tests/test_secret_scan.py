import importlib.util
import subprocess
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "secret_scan", Path(__file__).resolve().parents[1] / "scripts" / "secret_scan.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


def kinds(text):
    return [k for k, _, _ in scan.policy_hits(text)]


def test_lan_ips_are_flagged_and_documentation_range_is_not():
    assert kinds("gw 192.168.50.1") == ["policy:lan-ip"]  # secretscan: allow fixture
    assert kinds("host 10.0.0.5") == ["policy:lan-ip"]  # secretscan: allow fixture
    assert kinds("host 172.20.1.9") == ["policy:lan-ip"]  # secretscan: allow fixture
    assert kinds("doc 192.0.2.10 and 198.51.100.7") == []
    assert kinds("loopback 127.0.0.1 any 0.0.0.0") == []


def test_mac_allowlist_passes_fixture_prefixes_and_flags_real_ones():
    assert kinds("mac 02:00:00:00:00:1f") == []
    assert kinds("mac 00:00:5e:00:53:01") == []
    assert kinds("mac f4:5c:89:12:ab:cd") == ["policy:mac"]  # secretscan: allow fixture
    assert kinds("mac F4-5C-89-12-AB-CD") == ["policy:mac"]  # secretscan: allow fixture


def test_masking_never_returns_the_full_value():
    assert scan.mask_ip("192.168.50.1") == "192.168.x.x"  # secretscan: allow fixture
    assert scan.mask_mac("F4:5C:89:12:AB:CD") == "f4:5c:89:xx:xx:xx"  # secretscan: allow fixture


def test_self_test_passes_with_the_installed_engine(tmp_path):
    ok, missing = scan.self_test(tmp_path)
    assert ok and missing == []


def test_history_records_reads_real_git_history(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    env = ["git", "-C", str(repo)]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "x.py").write_text("keep = 1\nsecret_line = 2\n")
    subprocess.run(env + ["add", "."], check=True)
    subprocess.run(env + ["-c", "user.name=t", "-c", "user.email=t@example.test",
                          "commit", "-q", "-m", "one"], check=True)
    recs = scan.history_records(repo)
    assert [(p, n, c) for _, p, n, c in recs] == [
        ("x.py", 1, "keep = 1"), ("x.py", 2, "secret_line = 2")]
