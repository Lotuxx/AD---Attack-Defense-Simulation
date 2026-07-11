"""
Format Utilities
================
Terminal output helpers — colors, banners, menus, progress bars, tables.

All visual output in the framework goes through these utilities to ensure
consistent styling across all modules and the CLI layer.

Color support is automatically disabled when stdout is not a TTY
(e.g. when output is piped to a file or CI environment).
"""

import os
import sys
import shutil


class Colors:
    """
    ANSI escape codes for terminal text styling.

    Automatically disabled when stdout is not a TTY to avoid
    polluting redirected output with raw escape sequences.
    """
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

    # Strip all color codes when not writing to a real terminal
    if not sys.stdout.isatty():
        RESET = BOLD = DIM = RED = GREEN = YELLOW = ""
        BLUE  = MAGENTA = CYAN = WHITE = ""


# ── ASCII Banner ──────────────────────────────────────────────────────────────

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
    """Return the current terminal width, defaulting to 100 columns."""
    return shutil.get_terminal_size((100, 30)).columns


def print_banner():
    """Print the full ASCII art banner with title and authors."""
    width = term_width()
    sep   = Colors.CYAN + "═" * width + Colors.RESET

    print(sep)
    print(Colors.CYAN + Colors.BOLD + BANNER + Colors.RESET)
    print(Colors.WHITE + Colors.BOLD + SUBTITLE.center(width) + Colors.RESET)
    print(Colors.DIM   + AUTHORS.center(width) + Colors.RESET)
    print(sep)
    print()


def print_separator(title: str = ""):
    """
    Print a horizontal separator line, optionally with a centered title.

    Args:
        title (str): Optional title text displayed in the center of the line.
    """
    width = term_width()
    if title:
        pad  = (width - len(title) - 4) // 2
        line = (Colors.CYAN + "─" * pad +
                f"[ {Colors.WHITE}{Colors.BOLD}{title}{Colors.RESET}{Colors.CYAN} ]" +
                "─" * pad + Colors.RESET)
    else:
        line = Colors.CYAN + "─" * width + Colors.RESET
    print(f"\n{line}\n")


def print_menu(title: str, items: list):
    """
    Print a formatted menu with a title and numbered options.

    Args:
        title (str)        : Menu section title displayed in the separator.
        items (list[tuple]): List of (key, label) pairs for each menu option.
                             Option "0" is automatically styled in red (exit/back).
    """
    print_separator(title)
    for key, label in items:
        # Highlight the exit/back option in red for visual distinction
        color = Colors.RED if key == "0" else Colors.CYAN
        print(f"  {color}[{key}]{Colors.RESET}  {label}")


# ── Status message helpers ────────────────────────────────────────────────────

def print_success(msg: str):
    """Print a green success message with a checkmark icon."""
    print(f"{Colors.GREEN}[✔] {msg}{Colors.RESET}")


def print_error(msg: str):
    """Print a red error message with a cross icon."""
    print(f"{Colors.RED}[✘] {msg}{Colors.RESET}")


def print_warning(msg: str):
    """Print a yellow warning message with an exclamation icon."""
    print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")


def print_info(msg: str):
    """Print a blue informational message with an 'i' icon."""
    print(f"{Colors.BLUE}[i] {msg}{Colors.RESET}")


# ── Progress bar ──────────────────────────────────────────────────────────────

def print_step(step: int, total: int, msg: str):
    """
    Print an inline progress bar for multi-step operations (e.g. playbooks).

    Uses carriage return (\r) to update in place on the same line.
    Prints a newline when the last step is reached.

    Args:
        step  (int): Current step number (1-based).
        total (int): Total number of steps.
        msg   (str): Label for the current step.
    """
    # Calculate how many blocks to fill (out of 20)
    pct = int((step / total) * 20)
    bar = Colors.GREEN + "█" * pct + Colors.DIM + "░" * (20 - pct) + Colors.RESET
    print(f"\r  [{bar}] {step}/{total}  {msg}", end="", flush=True)
    # Move to next line when all steps are done
    if step == total:
        print()


# ── Table formatter ───────────────────────────────────────────────────────────

def format_table(headers: list, rows: list) -> str:
    """
    Render a simple ASCII table with auto-sized columns.

    Args:
        headers (list[str])       : Column header names.
        rows    (list[list[str]]) : Table data rows.

    Returns:
        str: Multi-line ASCII table string ready for printing.

    Example:
        print(format_table(["Name", "Status"], [["audit_passwords", "OK"]]))
    """
    # Calculate the maximum width needed for each column
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Build separator and format strings
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"

    lines = [sep, fmt.format(*headers), sep]
    for row in rows:
        lines.append(fmt.format(*[str(c) for c in row]))
    lines.append(sep)
    return "\n".join(lines)


def risk_badge(level: str) -> str:
    """
    Return a color-coded risk badge string for display in terminal output.

    Args:
        level (str): Risk level — 'Critique', 'Élevé', 'Moyen', 'Faible', 'Info'

    Returns:
        str: Colored badge string, e.g. '\033[91m[Critique]\033[0m'
    """
    colors = {
        "Critique": Colors.RED,
        "Élevé":    Colors.RED,
        "Critical": Colors.RED,
        "High":     Colors.RED,
        "Moyen":    Colors.YELLOW,
        "Medium":   Colors.YELLOW,
        "Faible":   Colors.GREEN,
        "Low":      Colors.GREEN,
        "Info":     Colors.BLUE,
    }
    c = colors.get(level, Colors.WHITE)
    return f"{c}[{level}]{Colors.RESET}"
