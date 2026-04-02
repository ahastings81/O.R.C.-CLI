# O.R.C.-CLI

**O.R.C.-CLI** is an open-source execution firewall for AI agents.

It intercepts terminal commands before they run, scores risk, explains why a command may be dangerous, and gives the user the final decision to approve, deny, or edit execution.

## Why it exists

AI agents are getting direct access to terminals.

That is powerful — and dangerous.

O.R.C.-CLI adds a simple control layer between AI-generated commands and your machine.

## Features

- Intercepts commands before execution
- Scores command risk as LOW, MEDIUM, or HIGH
- Explains why a command was flagged
- Lets the user approve, deny, or edit execution
- Logs all decisions to a local JSONL audit log
- Supports one-off command review and interactive shell mode

## Install

Clone the repo:

```bash
git clone https://github.com/ahastings81/O.R.C.-CLI.git
cd O.R.C.-CLI

## Example

```bash
python orc.py "rm -rf /"
