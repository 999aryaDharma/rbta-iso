"""Script validasi kepemilikan dan permission direktori state produksi."""

import argparse
import os
from pathlib import Path
import stat
import sys

REQUIRED_UID = 10001
REQUIRED_GID = 10001


def check_state_dir_permissions(
    state_dir: Path,
    target_uid: int = REQUIRED_UID,
    target_gid: int = REQUIRED_GID,
) -> tuple[bool, str]:
    """Validasi bahwa direktori state memenuhi kontrak kepemilikan UID/GID non-root dan izin tulis/eksekusi yang aman.

    Parameters
    ----------
    state_dir : Path
        Direktori tujuan yang diperiksa.
    target_uid : int
        UID pemilik yang diharapkan (default 10001).
    target_gid : int
        GID pemilik yang diharapkan (default 10001).

    Returns
    -------
    tuple[bool, str]
        (is_valid, message)
    """
    state_dir = state_dir.resolve()
    if not state_dir.exists():
        return False, f"State directory '{state_dir}' does not exist."
    if not state_dir.is_dir():
        return False, f"Path '{state_dir}' is not a directory."

    # Cek kepemilikan UID/GID numerik dan mode permission di POSIX.
    if os.name == "posix":
        st = os.stat(state_dir)
        uid = st.st_uid
        gid = st.st_gid
        mode = st.st_mode

        if uid != target_uid or gid != target_gid:
            return False, (
                f"State directory '{state_dir}' is owned by UID:GID {uid}:{gid}, "
                f"but production runtime requires {target_uid}:{target_gid}.\n"
                f"Remediation (run on host):\n"
                f"  sudo chown -R {target_uid}:{target_gid} {state_dir}\n"
                f"  sudo chmod 0750 {state_dir}"
            )

        if not (mode & stat.S_IWUSR):
            return False, (
                f"State directory '{state_dir}' is not writable by owner (mode: {oct(mode)}).\n"
                f"Remediation (run on host):\n"
                f"  sudo chmod 0750 {state_dir}"
            )

        if not (mode & stat.S_IXUSR):
            return False, (
                f"State directory '{state_dir}' is not executable/traversable by owner (mode: {oct(mode)}).\n"
                f"Directories require execute permission for container UID {target_uid} to access files within.\n"
                f"Remediation (run on host):\n"
                f"  sudo chmod 0750 {state_dir}"
            )

        if mode & stat.S_IWOTH:
            return False, (
                f"State directory '{state_dir}' has world-writable permissions ({oct(mode)}). "
                f"World-writable chmod 777 is strictly forbidden.\n"
                f"Remediation (run on host):\n"
                f"  sudo chmod 0750 {state_dir}"
            )

        return True, f"PASS: State directory '{state_dir}' verified owned by {target_uid}:{target_gid} with secure permissions ({oct(mode)})."

    # Fallback non-POSIX (workstation development Windows).
    test_file = state_dir / f".preflight_test_{os.getpid()}"
    try:
        test_file.touch()
        test_file.unlink()
        return True, f"PASS: State directory '{state_dir}' is writable (non-POSIX host fallback)."
    except Exception as exc:
        return False, f"State directory '{state_dir}' is not writable: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate state directory ownership and permissions.")
    parser.add_argument("--state-dir", required=True, type=Path, help="Path to state directory.")
    parser.add_argument("--target-uid", default=REQUIRED_UID, type=int, help="Required owner UID.")
    parser.add_argument("--target-gid", default=REQUIRED_GID, type=int, help="Required owner GID.")
    args = parser.parse_args()

    is_valid, msg = check_state_dir_permissions(
        state_dir=args.state_dir,
        target_uid=args.target_uid,
        target_gid=args.target_gid,
    )

    if is_valid:
        print(msg)
        return 0
    else:
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
