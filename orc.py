#!/usr/bin/env python3
"""
O.R.C. - OrClawstrate CLI MVP
A simple execution firewall for terminal commands.

Features:
- Intercepts commands before execution
- Scores basic command risk
- Explains why a command is risky
- Lets the user approve, deny, or edit the command
- Logs all actions to a JSONL log file

Examples:
    python orc.py "dir"
    python orc.py "ls -la"
    python orc.py "rm -rf /"
    python orc.py --shell
"""

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path


LOG_FILE = Path("orc_log.jsonl")


def utc_now_iso():
    return datetime.utcnow().isoformat() + "Z"


def is_windows():
    return platform.system().lower() == "windows"


def print_banner():
    print("=" * 60)
    print("O.R.C. - OrClawstrate CLI MVP")
    print("AI execution firewall for terminal commands")
    print("=" * 60)


def normalize_command(command: str) -> str:
    return command.strip()


def split_command(command: str):
    """
    Best-effort tokenization.
    Falls back to plain split if shlex fails.
    """
    try:
        if is_windows():
            return shlex.split(command, posix=False)
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def analyze_command(command: str):
    """
    Returns:
        {
            "risk": "LOW" | "MEDIUM" | "HIGH",
            "score": int,
            "reasons": list[str],
            "categories": list[str]
        }
    """
    cmd = command.lower().strip()
    tokens = split_command(cmd)

    score = 0
    reasons = []
    categories = []

    def add(points, reason, category):
        nonlocal score
        score += points
        reasons.append(reason)
        if category not in categories:
            categories.append(category)

    # Dangerous deletion patterns
    if "rm -rf /" in cmd or "rm -rf /*" in cmd:
        add(100, "Recursive root deletion detected.", "destructive")

    if "del /f /s /q" in cmd:
        add(80, "Forced recursive file deletion detected.", "destructive")

    if "format " in cmd:
        add(90, "Disk format command detected.", "destructive")

    if "mkfs" in cmd:
        add(90, "Filesystem creation command detected.", "destructive")

    if "dd " in cmd and " of=/dev/" in cmd:
        add(95, "Raw disk write detected.", "destructive")

    # Generic deletion
    if tokens and tokens[0] in {"rm", "rmdir", "del", "erase"}:
        add(35, "File or directory deletion command detected.", "filesystem")

    # File move/copy/write-ish behavior
    if tokens and tokens[0] in {"mv", "move", "cp", "copy", "xcopy", "robocopy"}:
        add(15, "File modification or movement command detected.", "filesystem")

    # Package / dependency changes
    if "pip install" in cmd or "pip uninstall" in cmd:
        add(20, "Python package environment change detected.", "dependencies")

    if "npm install" in cmd or "npm uninstall" in cmd or "npm update" in cmd:
        add(20, "Node package environment change detected.", "dependencies")

    if "apt install" in cmd or "apt remove" in cmd or "yum install" in cmd or "dnf install" in cmd:
        add(25, "System package change detected.", "dependencies")

    # Publishing / deployment
    if "npm publish" in cmd:
        add(60, "Publishing to public package registry detected.", "deployment")

    if "twine upload" in cmd:
        add(60, "Python package upload detected.", "deployment")

    if "docker push" in cmd:
        add(45, "Container image push detected.", "deployment")

    if "git push" in cmd:
        add(30, "Remote repository push detected.", "source_control")

    if "git reset --hard" in cmd:
        add(50, "Destructive git reset detected.", "source_control")

    if "git clean -fd" in cmd or "git clean -fdx" in cmd:
        add(50, "Untracked files deletion detected.", "source_control")

    # Network / remote execution
    if "curl " in cmd or "wget " in cmd or "invoke-webrequest" in cmd:
        add(20, "Network retrieval command detected.", "network")

    if "ssh " in cmd or "scp " in cmd or "sftp " in cmd:
        add(35, "Remote access or transfer command detected.", "network")

    # Shell chaining / multiple commands
    if "&&" in cmd or "||" in cmd or ";" in cmd:
        add(15, "Multiple chained commands detected.", "shell_logic")

    # Elevated privilege attempts
    if cmd.startswith("sudo "):
        add(40, "Elevated privilege execution detected.", "privilege")

    if "powershell -executionpolicy bypass" in cmd:
        add(55, "PowerShell execution policy bypass detected.", "privilege")

    # Script execution
    if tokens and any(tokens[0].endswith(ext) for ext in [".sh", ".bat", ".cmd", ".ps1", ".py"]):
        add(20, "Direct script execution detected.", "execution")

    if tokens and tokens[0] in {"bash", "sh", "powershell", "pwsh", "python", "python3", "cmd"}:
        add(10, "Interpreter or shell execution detected.", "execution")

    # Wildcards can increase blast radius
    if "*" in cmd:
        add(10, "Wildcard usage detected.", "scope")

    # Environment variable / secret-ish exposure
    if "printenv" in cmd or "env" == cmd or "set " in cmd:
        add(15, "Environment inspection detected.", "secrets")

    # Risk label
    if score >= 70:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "categories": categories,
    }


def log_event(event: dict):
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def print_analysis(command: str, analysis: dict):
    print("\n[O.R.C.] Intercepted command:")
    print(f"  {command}\n")
    print(f"Risk: {analysis['risk']}")
    print(f"Score: {analysis['score']}")

    if analysis["categories"]:
        print("Categories: " + ", ".join(analysis["categories"]))

    if analysis["reasons"]:
        print("Reasons:")
        for reason in analysis["reasons"]:
            print(f"  - {reason}")
    else:
        print("Reasons:")
        print("  - No specific high-risk patterns detected.")


def get_user_decision(analysis: dict):
    if analysis["risk"] == "HIGH":
        prompt = "\nAction? [deny/edit/approve]: "
    elif analysis["risk"] == "MEDIUM":
        prompt = "\nAction? [approve/edit/deny]: "
    else:
        prompt = "\nAction? [approve/edit/deny]: "

    while True:
        try:
            choice = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "abort"
        if choice in {"approve", "a"}:
            return "approve"
        if choice in {"deny", "d"}:
            return "deny"
        if choice in {"edit", "e"}:
            return "edit"
        print("Please enter approve, deny, or edit.")


def execute_command(command: str):
    """
    Executes the command in the user's shell.
    Returns a dict with exit code, stdout, stderr.
    """
    tokens = split_command(command.lower())
    interactive_roots = {
        "python",
        "python3",
        "py",
        "bash",
        "sh",
        "cmd",
        "powershell",
        "pwsh",
    }
    is_interactive = bool(tokens) and tokens[0] in interactive_roots

    try:
        if is_interactive:
            completed = subprocess.run(
                command,
                shell=True,
                text=True,
            )
            return {
                "returncode": completed.returncode,
                "stdout": "",
                "stderr": "",
                "interrupted": False,
                "interactive": True,
            }

        completed = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=True
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "interrupted": False,
            "interactive": False,
        }
    except KeyboardInterrupt:
        return {
            "returncode": 130,
            "stdout": "",
            "stderr": "",
            "interrupted": True,
            "interactive": is_interactive,
        }


def review_and_run(command: str):
    original_command = normalize_command(command)

    while True:
        analysis = analyze_command(original_command)
        print_analysis(original_command, analysis)

        decision = get_user_decision(analysis)

        if decision == "abort":
            print("\n[O.R.C.] Review cancelled. Nothing was executed.")
            return 130

        if decision == "deny":
            event = {
                "timestamp": utc_now_iso(),
                "command": original_command,
                "decision": "DENIED",
                "risk": analysis["risk"],
                "score": analysis["score"],
                "reasons": analysis["reasons"],
                "categories": analysis["categories"],
                "result": None,
            }
            log_event(event)
            print("\n[O.R.C.] Command denied. Nothing was executed.")
            return 1

        if decision == "edit":
            try:
                edited = input("\nEnter edited command: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[O.R.C.] Edit cancelled. Keeping original command.")
                continue
            if not edited:
                print("[O.R.C.] Edited command was empty. Keeping original command.")
            else:
                original_command = edited
            continue

        if decision == "approve":
            print("\n[O.R.C.] Executing approved command...\n")
            result = execute_command(original_command)

            event = {
                "timestamp": utc_now_iso(),
                "command": original_command,
                "decision": "APPROVED",
                "risk": analysis["risk"],
                "score": analysis["score"],
                "reasons": analysis["reasons"],
                "categories": analysis["categories"],
                "result": {
                    "returncode": result["returncode"],
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "interrupted": result["interrupted"],
                    "interactive": result["interactive"],
                },
            }
            log_event(event)

            if result["interrupted"]:
                print("\n[O.R.C.] Command interrupted by user.")
                return result["returncode"]

            if result["stdout"]:
                print(result["stdout"], end="" if result["stdout"].endswith("\n") else "\n")
            if result["stderr"]:
                print(result["stderr"], end="" if result["stderr"].endswith("\n") else "\n", file=sys.stderr)

            print(f"\n[O.R.C.] Process exited with code {result['returncode']}")
            return result["returncode"]


def interactive_shell():
    print("\nEntering O.R.C. shell mode.")
    print("Type commands to intercept and review.")
    print("Type 'exit' or 'quit' to leave.\n")

    while True:
        try:
            command = input("orc> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting O.R.C. shell.")
            return 0

        if not command:
            continue

        if command.lower() in {"exit", "quit"}:
            print("Exiting O.R.C. shell.")
            return 0

        review_and_run(command)


def parse_args():
    parser = argparse.ArgumentParser(
        description="O.R.C. - AI execution firewall CLI MVP"
    )
    parser.add_argument(
        "command",
        nargs="?",
        help='Command to intercept, for example: "git push origin main"'
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="Start interactive O.R.C. shell mode"
    )
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    if args.shell:
        return interactive_shell()

    if args.command:
        return review_and_run(args.command)

    print("\nNo command provided.")
    print("Examples:")
    print('  python orc.py "dir"')
    print('  python orc.py "ls -la"')
    print('  python orc.py "git push origin main"')
    print('  python orc.py --shell')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
