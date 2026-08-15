"""Repeatable local PostgreSQL copy-engine isolation smoke test.

Requires initdb, pg_ctl, pg_basebackup, and psycopg. It uses a temporary
PostgreSQL cluster and leaves it running so a later handoff can inspect it.
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import psycopg


def main():
    missing = [x for x in ("initdb", "pg_ctl", "pg_basebackup") if shutil.which(x) is None]
    if missing:
        raise SystemExit("missing PostgreSQL binaries: " + ", ".join(missing))
    root = Path(tempfile.mkdtemp(prefix="mosaic-db-e2e-"))
    main_dir, branch_dir = root / "main", root / "branch"
    port, branch_port = 56432, 56433
    subprocess.run(["initdb", "-D", str(main_dir), "--auth=trust"], check=True, capture_output=True)
    subprocess.run(["pg_ctl", "-D", str(main_dir), "-o", f"-p {port}", "-w", "start"], check=True, capture_output=True)
    subprocess.run(["createdb", "-p", str(port), "postgres"], check=False, capture_output=True)
    try:
        with psycopg.connect(host="127.0.0.1", port=port, user=os.getenv("USER", "postgres"), dbname="postgres") as conn:
            conn.execute("CREATE TABLE isolated (side text, value int)")
            conn.execute("INSERT INTO isolated VALUES ('main', 1)")
            conn.commit()
        subprocess.run(["pg_basebackup", "-D", str(branch_dir), "-h", "127.0.0.1", "-p", str(port), "-U", os.getenv("USER", "postgres"), "-Fp", "-X", "stream", "-R"], check=True)
        subprocess.run(["pg_ctl", "-D", str(branch_dir), "-o", f"-p {branch_port}", "-w", "start"], check=True, capture_output=True)
        subprocess.run(["pg_ctl", "-D", str(branch_dir), "promote", "-w"], check=True, capture_output=True)
        with psycopg.connect(host="127.0.0.1", port=branch_port, user=os.getenv("USER", "postgres"), dbname="postgres") as conn:
            conn.execute("INSERT INTO isolated VALUES ('branch', 2)")
            conn.commit()
            branch_rows = conn.execute("SELECT side,value FROM isolated ORDER BY value").fetchall()
        with psycopg.connect(host="127.0.0.1", port=port, user=os.getenv("USER", "postgres"), dbname="postgres") as conn:
            main_rows = conn.execute("SELECT side,value FROM isolated ORDER BY value").fetchall()
        assert main_rows == [("main", 1)]
        assert branch_rows == [("main", 1), ("branch", 2)]
        print(f"e2e ok: main={main_rows} branch={branch_rows} branch_path={branch_dir}")
    finally:
        subprocess.run(["pg_ctl", "-D", str(branch_dir), "-m", "fast", "-w", "stop"], check=False, capture_output=True)
        subprocess.run(["pg_ctl", "-D", str(main_dir), "-m", "fast", "-w", "stop"], check=False, capture_output=True)
        print(f"postgres data preserved at {root}")


if __name__ == "__main__":
    main()
