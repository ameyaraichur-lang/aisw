"""Run the whole product on this machine: PostgreSQL, OPA, API, worker and the console.

    backend/.venv/bin/python tools/dev_stack.py up [--ai] [--tls-inspection-ca PEM]
    backend/.venv/bin/python tools/dev_stack.py down
    backend/.venv/bin/python tools/dev_stack.py reset

Development mode only (AISW_ENV=dev): sign-in is the development identity picker, manifests are
signed with a local key, and the audit witness is a local file. Logs, evidence, the witness and
scanner output live in data/dev-stack/. The database (PostgreSQL cannot use a path with spaces for
its socket), the signing key and every credential live in ~/.aisw-dev/, outside the repository;
credentials are files read through AISW_SECRETS_DIR, never environment variables. Everything
survives restarts; `reset` empties the database, evidence and witness.
Ctrl-C (or `down` from another terminal) stops every process, including the embedded database.
OPA is restarted if it exits: one malformed connection, such as a port scanner's probe, stops its
listener.

--ai        enable Astra with the settings in .env.astra (never printed). Pass
            --ai-approval-ref to record which data approval covers the targets you assess.
--ca-file   PEM bundle the worker trusts for target TLS (SSL_CERT_FILE). Without it the platform
            default trust store is used.
--tls-inspection-ca
            PEM of the network's TLS-inspection root, when this machine's traffic is re-signed by a
            corporate proxy. URL probes then report inspected connections instead of failing the
            target's certificate. Never put this root in --ca-file as well.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
BACKEND, WEB = ROOT / "backend", ROOT / "web"
STATE = ROOT / "data" / "dev-stack"
PY = BACKEND / ".venv" / "bin" / "python"
DEV_HOME = Path(os.environ.get("AISW_DEV_HOME", Path.home() / ".aisw-dev"))
PGDATA = Path(os.environ.get("AISW_DEV_PGDATA", DEV_HOME / "pg"))
SECRETS = DEV_HOME / "secrets"  # read by the services as AISW_SECRETS_DIR
DB = "aisw"
PIDS = STATE / "pids"


def secret(name: str, value: str | None = None) -> Path:
    """A 0600 file in SECRETS: ``value`` is (re)written; without one, a random value is kept."""
    path = SECRETS / name
    if value is not None or not path.exists():
        SECRETS.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(value if value is not None else secrets.token_urlsafe(32))
        path.chmod(0o600)
    return path


def read_env_file(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def wait_http(url: str, seconds: float, procs: list[subprocess.Popen[bytes]]) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for p in procs:
            if p.poll() is not None:
                raise SystemExit(
                    f"a process exited early (code {p.returncode}); see {STATE / 'logs'}"
                )
        try:
            with opener.open(url, timeout=2):  # noqa: S310 - loopback only
                return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise SystemExit(f"{url} did not answer within {seconds:.0f}s; see {STATE / 'logs'}")


def up(args: argparse.Namespace) -> int:
    import pgserver  # type: ignore[import-untyped]
    from sqlalchemy import URL, create_engine, text

    for d in (STATE / "logs", STATE / "evidence", DEV_HOME / "keys"):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    print("starting PostgreSQL ...", flush=True)
    if " " in str(PGDATA):
        raise SystemExit(f"{PGDATA}: PostgreSQL cannot use a path with spaces; set AISW_DEV_PGDATA")
    PGDATA.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pg = pgserver.get_server(PGDATA, cleanup_mode="stop")
    host = parse_qs(urlparse(pg.get_uri()).query)["host"][0]
    admin = create_engine(
        f"postgresql+psycopg://postgres@/postgres?host={host}", isolation_level="AUTOCOMMIT"
    )
    with admin.connect() as c:
        if not c.execute(text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": DB}).first():
            c.execute(text(f'CREATE DATABASE "{DB}"'))
    admin.dispose()

    def db_url(user: str, password_file: str | None = None) -> str:
        password = secret(password_file).read_text() if password_file else None
        return URL.create("postgresql+psycopg", username=user, password=password, database=DB,
                          query={"host": host}).render_as_string(hide_password=False)  # fmt: skip

    secret("aisw_database_url", db_url("aisw_app", "pg_app_password"))  # socket dir may move
    secret("aisw_worker_database_url", db_url("aisw_worker", "pg_worker_password"))
    secret("aisw_session_secret")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AISW_")}
    env.update({
        "AISW_ENV": "dev", "AISW_DEV_AUTH_STUB": "true", "AISW_SECRETS_DIR": str(SECRETS),
        "AISW_SIGNING_KEY_PATH": str(DEV_HOME / "keys" / "manifest-signing.pem"),
        "AISW_EVIDENCE_DIR": str(STATE / "evidence"),
        "AISW_API_PORT": str(args.api_port),
        "AISW_POLICY_ENGINE": "opa", "AISW_OPA_URL": f"http://127.0.0.1:{args.opa_port}",
        "AISW_AUDIT_WITNESS": "local_file", "AISW_AUDIT_WITNESS_PATH": str(STATE / "witness.log"),
        "AISW_WORKER_HEARTBEAT_FILE": str(STATE / "worker.heartbeat"),
    })  # fmt: skip
    if args.ai:
        astra = ROOT / ".env.astra"
        if not astra.is_file():
            raise SystemExit(".env.astra is missing; --ai needs it")
        env.update({k: v for k, v in read_env_file(astra).items() if k.startswith("AISW_")})
        if args.ai_approval_ref:
            env["AISW_ASTRA_DATA_APPROVAL_REF"] = args.ai_approval_ref
    if args.ca_file:
        env["SSL_CERT_FILE"] = str(Path(args.ca_file).resolve())
    if args.tls_inspection_ca:
        env["AISW_TLS_INSPECTION_CA_FILE"] = str(Path(args.tls_inspection_ca).resolve())

    owner_url = secret("owner_url", db_url("postgres"))
    print("applying migrations and enabling the service roles ...", flush=True)
    boot = subprocess.run(  # noqa: S603
        [str(PY), "-m", "aisw.bootstrap", "--app-password-file", str(secret("pg_app_password")),
         "--worker-password-file", str(secret("pg_worker_password"))],
        cwd=BACKEND, env={**env, "AISW_MIGRATION_DATABASE_URL_FILE": str(owner_url)},
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if boot.returncode != 0:
        pg.cleanup()
        raise SystemExit(f"bootstrap failed:\n{boot.stderr[-2000:]}")

    procs: list[subprocess.Popen[bytes]] = []
    PIDS.write_text(f"launcher {os.getpid()}\n")

    def start(
        name: str, cmd: list[str], cwd: Path, extra: dict[str, str] | None = None
    ) -> subprocess.Popen[bytes]:
        log = (STATE / "logs" / f"{name}.log").open("ab")
        p = subprocess.Popen(cmd, cwd=cwd, env={**env, **(extra or {})}, stdout=log,  # noqa: S603
                             stderr=subprocess.STDOUT, start_new_session=True)  # fmt: skip
        procs.append(p)
        with PIDS.open("a") as fh:
            fh.write(f"{name} {p.pid}\n")
        return p

    def shutdown(*_: object) -> None:
        for p in reversed(procs):
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
        pg.cleanup()
        PIDS.unlink(missing_ok=True)
        print("stopped", flush=True)

    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        opa_bin = os.environ.get("OPA_BIN", str(Path.home() / ".local" / "bin" / "opa"))
        opa_cmd = [opa_bin, "run", "--server", "--addr", f"127.0.0.1:{args.opa_port}", "--skip-version-check",
                   "--log-level", "error", "--ignore", "*_test.rego", str(BACKEND / "aisw/policy/rego")]  # fmt: skip
        opa = start("opa", opa_cmd, ROOT)
        wait_http(f"http://127.0.0.1:{args.opa_port}/health", 30, procs)
        start("api", [str(PY), "-m", "aisw.api"], BACKEND)
        wait_http(f"http://127.0.0.1:{args.api_port}/healthz", 60, procs)
        start(
            "worker", [str(PY), "-m", "aisw.orchestrator", "--worker-id", "dev-worker-1"], BACKEND
        )
        start("web", ["npm", "run", "dev", "--", "--port", str(args.web_port), "--strictPort", "--host", "127.0.0.1"],
              WEB, {"AISW_API_URL": f"http://127.0.0.1:{args.api_port}"})  # fmt: skip
        wait_http(f"http://127.0.0.1:{args.web_port}/", 60, procs)
        ai = f"on ({env.get('AISW_MODEL_ID')})" if args.ai else "off"
        print(f"\nAISW is running: http://127.0.0.1:{args.web_port}/   (AI {ai}; logs in {STATE / 'logs'})",
              flush=True)  # fmt: skip
        print("Pick a development identity to sign in. Ctrl-C stops everything.", flush=True)
        while True:
            time.sleep(1)
            if opa.poll() is not None:
                print(f"OPA exited (code {opa.returncode}); restarting it", flush=True)
                procs.remove(opa)
                opa = start("opa", opa_cmd, ROOT)
            if any(p.poll() is not None for p in procs if p is not opa):
                break
        print("a process exited; stopping the stack", flush=True)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        shutdown()


def down() -> int:
    """Stop a stack started elsewhere: the launcher cleans up; leftovers are stopped directly."""
    if not PIDS.exists():
        print("no stack is running")
        return 0
    entries = [line.split() for line in PIDS.read_text().splitlines() if line.strip()]
    launcher = next((int(pid) for name, pid in entries if name == "launcher"), None)
    if launcher is not None:
        try:
            os.kill(launcher, signal.SIGTERM)
            for _ in range(40):
                time.sleep(0.5)
                if not PIDS.exists():
                    print("stopped")
                    return 0
        except ProcessLookupError:
            pass
    for name, pid in reversed(entries):
        if name != "launcher":
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid), signal.SIGTERM)
    if (PGDATA / "postmaster.pid").exists():
        import pgserver  # type: ignore[import-untyped]

        ctl = Path(pgserver.__file__).parent / "pginstall" / "bin" / "pg_ctl"
        subprocess.run([str(ctl), "-D", str(PGDATA), "stop", "-m", "fast"], check=False)  # noqa: S603
    PIDS.unlink(missing_ok=True)
    print("stopped (the launcher was not running; its processes were stopped directly)")
    return 0


def reset() -> int:
    """Delete the database, evidence and audit witness so the next ``up`` starts empty. The signing
    key, credentials, the inspection CA and scan files are kept."""
    if PIDS.exists():
        print("the stack is running; run `down` first", file=sys.stderr)
        return 1
    for path in (PGDATA, STATE / "evidence"):
        shutil.rmtree(path, ignore_errors=True)
    (STATE / "witness.log").unlink(missing_ok=True)
    print(f"removed {PGDATA}, {STATE / 'evidence'} and the audit witness")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools/dev_stack.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up", help="start everything in the foreground")
    u.add_argument("--ai", action="store_true", help="enable Astra from .env.astra")
    u.add_argument("--ai-approval-ref", help="data approval reference for the assessed targets")
    u.add_argument("--ca-file", help="PEM bundle the worker trusts for target TLS")
    u.add_argument("--tls-inspection-ca", help="PEM of the network's TLS-inspection root")
    u.add_argument("--api-port", type=int, default=8000)
    u.add_argument("--web-port", type=int, default=5173)
    u.add_argument("--opa-port", type=int, default=8181)
    sub.add_parser("down", help="stop a running stack")
    sub.add_parser("reset", help="delete the stopped stack's database, evidence and witness")
    args = ap.parse_args(argv)
    if Path(sys.prefix).resolve() != (BACKEND / ".venv").resolve():
        print(f"run this with {PY}", file=sys.stderr)
        return 2
    return {"up": up, "down": lambda _: down(), "reset": lambda _: reset()}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
