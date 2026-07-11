"""
SSH Tunnel Manager
==================
Automates and reuses a persistent SSH local-port-forward tunnel to the
OpenSearch API used by Purple Team modules.

Previously, this tunnel had to be opened manually before every Purple Team
run (`ssh -L 9200:localhost:9200 ...`); if it dropped, every OpenSearch
query failed silently. This module:

    1. Checks whether the local port already answers (a tunnel opened by a
       previous run, or manually, may still be alive) — if so, reuses it.
    2. Otherwise, if opensearch_ssh_host/opensearch_ssh_user are configured,
       spawns a background `ssh -f -N -L ...` process and records its PID
       in a small state file, so later calls — even from a separate CLI
       invocation — can find and reuse the same tunnel instead of stacking
       up new ones.
    3. If no SSH config is available, falls back to the previous behavior
       (assume a tunnel is managed manually) so nothing breaks for users
       who don't opt in.

This is best-effort automation for a lab environment, not a hardened SSH
client — timeouts and failures degrade gracefully to a warning rather than
raising, since Purple Team modules should still run in demo mode if the
tunnel can't be established.
"""

import os
import socket
import subprocess
import time

from utils.format_utils import print_info, print_success, print_warning, print_error

# PID/local-port state file so separate CLI invocations can find & reuse
# the same backgrounded ssh process instead of opening duplicate tunnels.
_STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".ssh_tunnel_state")


def ensure_tunnel(cfg) -> int:
    """
    Ensure a persistent SSH tunnel to OpenSearch is up; return the local port to use.

    Args:
        cfg (Config): Framework configuration (uses the opensearch_ssh_* /
                      opensearch_local_port / opensearch_remote_port fields).

    Returns:
        int: Local port OpenSearch should be reachable on. Returned even on
             failure (falls back to the configured/default local port) so
             callers can still attempt a direct connection.
    """
    local_port = getattr(cfg, "opensearch_local_port", 9200) or 9200

    # 1. Something already listening locally? (tunnel from a previous run, or manual)
    if _port_is_open("127.0.0.1", local_port):
        state = _read_state()
        if state and state.get("local_port") == local_port and _pid_alive(state.get("pid", -1)):
            print_info(f"Tunnel SSH OpenSearch déjà actif (PID {state['pid']}, port {local_port}).")
        else:
            print_info(f"Port {local_port} déjà occupé (tunnel existant, manuel ou d'une session précédente) — réutilisation.")
        return local_port

    # 2. No local listener. Do we have enough config to open one ourselves?
    ssh_host = getattr(cfg, "opensearch_ssh_host", None)
    ssh_user = getattr(cfg, "opensearch_ssh_user", None)
    if not ssh_host or not ssh_user:
        print_warning(
            "Aucun tunnel OpenSearch actif et opensearch_ssh_host/opensearch_ssh_user "
            "non configurés dans config.yaml — ouvrez le tunnel manuellement, ou "
            "renseignez ces champs pour l'automatiser."
        )
        return local_port

    ssh_port    = getattr(cfg, "opensearch_ssh_port", 22) or 22
    remote_port = getattr(cfg, "opensearch_remote_port", 9200) or 9200
    key_path    = getattr(cfg, "opensearch_ssh_key_path", None)

    if not _open_tunnel(ssh_host, ssh_user, ssh_port, local_port, remote_port, key_path):
        return local_port  # Failure already logged by _open_tunnel(); degrade gracefully

    print_success(f"Tunnel SSH OpenSearch actif sur le port {local_port}.")
    return local_port


def close_tunnel():
    """
    Terminate a tunnel previously opened by ensure_tunnel(), if this framework
    is the one that opened it (i.e. it's tracked in the state file).
    """
    state = _read_state()
    pid = state.get("pid")
    if pid and _pid_alive(pid):
        try:
            os.kill(pid, 15)  # SIGTERM
            print_info(f"Tunnel SSH OpenSearch (PID {pid}) fermé.")
        except Exception as e:
            print_warning(f"Impossible de fermer le tunnel SSH (PID {pid}) : {e}")
    if os.path.exists(_STATE_FILE):
        try:
            os.remove(_STATE_FILE)
        except Exception:
            pass


# ── Internals ─────────────────────────────────────────────────────────────────

def _open_tunnel(ssh_host: str, ssh_user: str, ssh_port: int,
                  local_port: int, remote_port: int, key_path: str = None) -> bool:
    """Spawn a backgrounded `ssh -f -N -L` tunnel and record its PID. Returns True on success."""
    cmd = [
        "ssh", "-f", "-N",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", str(ssh_port),
        "-L", f"{local_port}:localhost:{remote_port}",
    ]
    if key_path:
        cmd += ["-i", key_path]
    cmd.append(f"{ssh_user}@{ssh_host}")

    print_info(f"Ouverture du tunnel SSH OpenSearch ({ssh_user}@{ssh_host}:{ssh_port} -> localhost:{local_port})...")
    try:
        subprocess.run(cmd, check=True, timeout=15,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print_error(f"Échec de l'ouverture du tunnel SSH : {e.stderr.decode(errors='ignore') if e.stderr else e}")
        return False
    except FileNotFoundError:
        print_error("Client ssh introuvable sur cette machine.")
        return False
    except subprocess.TimeoutExpired:
        print_error("Timeout lors de l'ouverture du tunnel SSH (identifiants/clé/connectivité à vérifier).")
        return False

    # -f backgrounds ssh once the forward is set up; give the port a moment to appear
    for _ in range(10):
        if _port_is_open("127.0.0.1", local_port):
            break
        time.sleep(0.3)
    else:
        print_error(f"Le tunnel SSH s'est lancé mais le port {local_port} ne répond pas.")
        return False

    pid = _find_ssh_pid(local_port)
    if pid:
        _write_state(pid, local_port)
    return True


def _port_is_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return True if something is already listening/answering on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _find_ssh_pid(local_port: int):
    """Best-effort lookup of the backgrounded ssh -f process PID via pgrep."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", f"ssh -f -N .*-L {local_port}:"],
            capture_output=True, text=True, timeout=5
        )
        pids = [int(p) for p in result.stdout.split()]
        return pids[0] if pids else None
    except Exception:
        return None


def _read_state() -> dict:
    """Read the {pid, local_port} of a previously-opened tunnel, if any."""
    if not os.path.exists(_STATE_FILE):
        return {}
    try:
        with open(_STATE_FILE) as f:
            pid_str, port_str = f.read().strip().split(":")
            return {"pid": int(pid_str), "local_port": int(port_str)}
    except Exception:
        return {}


def _write_state(pid: int, local_port: int):
    try:
        with open(_STATE_FILE, "w") as f:
            f.write(f"{pid}:{local_port}")
    except Exception:
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False
