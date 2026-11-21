"""Copy text to the system clipboard using the tool each OS already has."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys


def _commands() -> list[list[str]]:
    if sys.platform == "darwin":
        return [["pbcopy"]]
    if sys.platform.startswith("win"):
        return [["clip"]]
    cmds = []
    if os.environ.get("WAYLAND_DISPLAY"):
        cmds.append(["wl-copy"])
    cmds += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    return cmds


def copy(text: str) -> bool:
    """Return True if the text was copied, False if no clipboard tool was found."""
    for cmd in _commands():
        if shutil.which(cmd[0]) is None:
            continue
        try:
            # Text goes in on stdin, never on the command line, so other users
            # can't see it in the process list.
            subprocess.run(cmd, input=text.encode("utf-8"), check=True, timeout=5)
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False
