"""
Format utilities — colors, banners, menus, output helpers.
"""

import os
import sys
import shutil


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    # Disable colors if not a tty
    if not sys.stdout.isatty():
        RESET = BOLD = DIM = RED = GREEN = YELLOW = ""
        BLUE = MAGENTA = CYAN = WHITE = ""


BANNER = r"""
  ██████╗ ██████╗      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
 ██╔══██╗██╔══██╗    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
 ███████║██║  ██║    ███████║   ██║      ██║   ███████║██║     █████╔╝ 
 ██╔══██║██║  ██║    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
 ██║  ██║██████╔╝    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
"""

SUBTITLE = "  ATTACKS & DEFENSE SIMULATION FRAMEWORK"
AUTHORS  = "  NISSEKONG Georges Owen  |  DIOP Salla  |  2025-2026"


def term_width() -> int:
    return shutil.get_terminal_size((100, 30)).columns


def print_banner():
    width = term_width()
    sep = Colors.CYAN + "═" * width + Colors.RESET

    print(sep)
    print(Colors.CYAN + Colors.BOLD + BANNER + Colors.RESET)
    print(Colors.WHITE + Colors.BOLD + SUBTITLE.center(width) + Colors.RESET)
    print(Colors.DIM + AUTHORS.center(width) + Colors.RESET)
    print(sep)
    print()


def print_separator(title: str = ""):
    width = term_width()
    if title:
        pad = (width - len(title) - 4) // 2
        line = Colors.CYAN + "─" * pad + f"[ {Colors.WHITE}{Colors.BOLD}{title}{Colors.RESET}{Colors.CYAN} ]" + "─" * pad + Colors.RESET
    else:
        line = Colors.CYAN + "─" * width + Colors.RESET
    print(f"\n{line}\n")


def print_menu(title: str, items: list):
    """
    items: list of (key, label) tuples
    """
    print_separator(title)
    for key, label in items:
        color = Colors.RED if key == "0" else Colors.CYAN
        print(f"  {color}[{key}]{Colors.RESET}  {label}")


def print_success(msg: str):
    print(f"{Colors.GREEN}[✔] {msg}{Colors.RESET}")


def print_error(msg: str):
    print(f"{Colors.RED}[✘] {msg}{Colors.RESET}")


def print_warning(msg: str):
    print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")


def print_info(msg: str):
    print(f"{Colors.BLUE}[i] {msg}{Colors.RESET}")


def print_step(step: int, total: int, msg: str):
    pct = int((step / total) * 20)
    bar = Colors.GREEN + "█" * pct + Colors.DIM + "░" * (20 - pct) + Colors.RESET
    print(f"\r  [{bar}] {step}/{total}  {msg}", end="", flush=True)
    if step == total:
        print()


def format_table(headers: list, rows: list) -> str:
    """Render a simple aligned table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    sep   = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    fmt   = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"

    lines = [sep, fmt.format(*headers), sep]
    for row in rows:
        lines.append(fmt.format(*[str(c) for c in row]))
    lines.append(sep)
    return "\n".join(lines)


def risk_badge(level: str) -> str:
    colors = {
        "Critique": Colors.RED,
        "Élevé":    Colors.RED,
        "Moyen":    Colors.YELLOW,
        "Faible":   Colors.GREEN,
        "Info":     Colors.BLUE,
    }
    c = colors.get(level, Colors.WHITE)
    return f"{c}[{level}]{Colors.RESET}"
