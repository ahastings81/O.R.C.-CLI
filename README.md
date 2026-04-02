O.R.C.-CLI

O.R.C.-CLI is an open-source execution firewall for AI agents.

It intercepts terminal commands before they run, scores risk, explains why a command may be dangerous, and gives the user the final decision to approve, deny, or edit execution.

Why it exists

AI agents are getting direct access to terminals.

That is powerful — and dangerous.

O.R.C.-CLI adds a simple control layer between AI-generated commands and your machine.

Features
Intercepts commands before execution
Scores command risk as LOW, MEDIUM, or HIGH
Explains why a command was flagged
Lets the user approve, deny, or edit execution
Logs all decisions to a local JSONL audit log
Supports one-off command review and interactive shell mode
Install

git clone https://github.com/ahastings81/O.R.C.-CLI.git

cd O.R.C.-CLI

Requirements
Python 3.10+

No external dependencies are required for the current MVP.

Usage

Run a single command:

python orc.py "git push origin main"

Start interactive mode:

python orc.py --shell

Example

python orc.py "rm -rf /"

Example output:

============================================================
O.R.C. - OrClawstrate CLI MVP
AI execution firewall for terminal commands

[O.R.C.] Intercepted command:
rm -rf /

Risk: HIGH
Score: 135
Categories: destructive, filesystem

Reasons:

Recursive root deletion detected.
File or directory deletion command detected.

Action? [deny/edit/approve]:

Audit log

Approved and denied commands are written to:

orc_log.jsonl

Current MVP limits
Risk detection is pattern-based
No GUI yet
No sandbox integration
No team policy sync
No rules file yet
Roadmap
Rules file support
Workspace/path restrictions
Agent pipe mode
Optional desktop UI
Sandbox connectors
Pluggable policy packs
Why open source

Trust is part of the product.

O.R.C.-CLI is intended to be inspectable, extensible, and easy for developers to test locally.

License

MIT
