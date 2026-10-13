"""ASCII art, banners and the boot sequence."""

from __future__ import annotations

import random
import time
from typing import List, Sequence, Tuple

from rich.align import Align
from rich.live import Live
from rich.table import Table
from rich.text import Text

from secure_repo import __author__, __version__
from secure_repo.cli.theme import CYAN, DIM, MAGENTA, NEON, VIOLET, console

GLYPHS = {
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "P": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    " ": ["  ", "  ", "  ", "  ", "  ", "  "],
    "/": ["    ██╗", "   ██╔╝", "  ██╔╝ ", " ██╔╝  ", "██╔╝   ", "╚═╝    "],
}
SMALL_BANNER = [
    r" ___ ___ ___ _   _ ___ ___   ___ ___ ___  ___  ",
    r"/ __| __/ __| | | | _ \ __| | _ \ __| _ \/ _ \ ",
    r"\__ \ _| (__| |_| |   / _|  |   / _||  _/ (_) |",
    r"|___/___\___|\___/|_|_\___| |_|_\___|_|  \___/ ",
]
_fx = random.Random()  # noqa: S311  cosmetic randomness for animations only - never used for security

GRADIENT = ["#00ff9c", "#00f5c4", "#00e5ff", "#4fc3ff", "#9d7bff", "#ff2e97"]

ART_NETWORK = [
    "  ●━━━━━●━━━━━●  ",
    "  ┃ ╲   ┃   ╱ ┃  ",
    "  ●━━━━━◉━━━━━●  ",
    "  ┃ ╱   ┃   ╲ ┃  ",
    "  ●━━━━━●━━━━━●  ",
]
ART_LOCK = [
    "    ▄▀▀▀▀▀▀▀▄    ",
    "    █ ▄▀▀▀▄ █    ",
    "    █ █   █ █    ",
    "  ▄▄█▄█▄▄▄█▄█▄▄  ",
    "  █░░░░░░░░░░░█  ",
    "  █░░░░▄█▄░░░░█  ",
    "  █░░░░▀█▀░░░░█  ",
    "  █░░░░░█░░░░░█  ",
    "  █▄▄▄▄▄▄▄▄▄▄▄█  ",
]
ART_RADAR = [
    "      .-~~~-.      ",
    "    .'   |   '.    ",
    "   /  .  |  .  \\   ",
    "  |-----(◉)-----|  ",
    "   \\  '  |  '  /   ",
    "    '.   |   .'    ",
    "      '-~~~-'      ",
]
ART_SKULL = [
    "     .-\"\"\"\"\"-.     ",
    "    /  _   _  \\    ",
    "   |  (x) (x)  |   ",
    "   |     ^     |   ",
    "    \\  '---'  /    ",
    "     '-.___.-'     ",
]
ART_SHIELD = [
    "    ▄▄▄▄▄▄▄▄▄▄▄    ",
    "    █░░░░░░░░░█    ",
    "    █░░░█▀█░░░█    ",
    "    █░░░▀▄▀░░░█    ",
    "     ▀▄░░░░░▄▀     ",
    "       ▀▄▄▄▀       ",
]
TAGLINES = [
    "repository security auditor",
    "static analysis :: secrets :: supply chain :: compliance",
    "see every weakness before an attacker does",
    "read-only. non-intrusive. evidence-driven.",
]


def banner_lines(width: int) -> List[str]:
    word = "SECURE REPO"
    rows = ["".join(GLYPHS[ch][row] for ch in word) for row in range(6)]
    if width >= len(rows[0]) + 4:
        return rows
    return SMALL_BANNER


def render_banner(width: int) -> Text:
    rows = banner_lines(width)
    text = Text()
    for index, row in enumerate(rows):
        text.append(row + "\n", style=f"bold {GRADIENT[min(index, len(GRADIENT) - 1)]}")
    return text


def glitch_reveal(duration: float = 0.9) -> None:
    """Reveal the banner with a 'decryption' effect."""
    rows = banner_lines(console.width)
    noise = "01#$%&@*<>/\\|=+-░▒▓"
    width = max(len(r) for r in rows)
    frames = 18
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        for frame in range(frames + 1):
            revealed = int(width * frame / frames)
            text = Text()
            for index, row in enumerate(rows):
                style = f"bold {GRADIENT[min(index, len(GRADIENT) - 1)]}"
                visible = row[:revealed]
                hidden = "".join(_fx.choice(noise) if ch != " " else " " for ch in row[revealed:])
                text.append(visible, style=style)
                text.append(hidden + "\n", style=f"{NEON} dim")
            live.update(text)
            time.sleep(duration / frames)


def matrix_rain(duration: float = 0.6) -> None:
    width = min(console.width, 100)
    chars = "0123456789abcdef"
    frames = int(duration / 0.04)
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        columns = [_fx.randint(-6, 0) for _ in range(width)]
        for _ in range(frames):
            lines = []
            for row in range(6):
                line = Text()
                for col in range(width):
                    head = columns[col]
                    if head - 4 <= row <= head:
                        style = "bold white" if row == head else f"{NEON}" if row > head - 2 else f"{NEON} dim"
                        line.append(_fx.choice(chars), style=style)
                    else:
                        line.append(" ")
                lines.append(line)
            columns = [c + 1 if _fx.random() > 0.2 else c for c in columns]
            live.update(Text("\n").join(lines))
            time.sleep(0.04)


def art_panel(art: Sequence[str], color: str = CYAN) -> Text:
    text = Text()
    for line in art:
        text.append(line + "\n", style=f"bold {color}")
    return text


def show_banner(animate: bool = True) -> None:
    console.print()
    if animate:
        matrix_rain()
        glitch_reveal()
    console.print(render_banner(console.width))
    info = Table.grid(padding=(0, 2))
    info.add_column()
    info.add_column()
    art = _fx.choice([ART_NETWORK, ART_LOCK, ART_RADAR, ART_SHIELD])
    details = Text()
    details.append("  ⟦ SECURE//REPO ⟧", style=f"bold {NEON}")
    details.append(f"  v{__version__}\n", style=DIM)
    details.append(f"  {_fx.choice(TAGLINES)}\n", style=f"italic {CYAN}")
    details.append("  author: ", style=DIM)
    details.append(f"{__author__}\n", style=f"bold {MAGENTA}")
    details.append("  mode  : ", style=DIM)
    details.append("authorized, read-only security auditing\n", style=VIOLET)
    details.append("  help  : ", style=DIM)
    details.append("secure-repo --help", style="bold white")
    info.add_row(art_panel(art, _fx.choice([CYAN, NEON, VIOLET])), details)
    console.print(info)


def boot_sequence(checks: List[Tuple[str, str, str]], animate: bool = True) -> None:
    """Print '[ OK ] name ....... value' lines, optionally with a small delay."""
    width = 44
    for status, name, value in checks:
        label = {"ok": ("[  OK  ]", NEON), "warn": ("[ WARN ]", "#ffd23f"), "fail": ("[ FAIL ]", "#ff2e63"),
                 "info": ("[ INFO ]", CYAN)}[status]
        line = Text()
        line.append(label[0], style=f"bold {label[1]}")
        line.append(" " + name + " ", style="white")
        line.append("." * max(3, width - len(name)), style="grey30")
        line.append(" " + value, style=label[1] if status != "ok" else CYAN)
        if animate:
            with console.status(Text(f" {name}", style=DIM), spinner="dots12", spinner_style=NEON):
                time.sleep(0.07 + _fx.random() * 0.08)
        console.print(line)


def section(title: str, color: str = NEON) -> None:
    console.print()
    console.rule(Text(f"⟦ {title} ⟧", style=f"bold {color}"), style="grey30", characters="─")


def big_status(ok: bool, text: str) -> None:
    art = ART_SHIELD if ok else ART_SKULL
    color = NEON if ok else "#ff2e63"
    grid = Table.grid(padding=(0, 3))
    grid.add_column()
    grid.add_column(vertical="middle")
    message = Text(text, style=f"bold {color}")
    grid.add_row(art_panel(art, color), message)
    console.print(Align.left(grid))
