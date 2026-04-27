#!/usr/bin/env python3
import argparse
import re
import subprocess
from pathlib import Path


REV_PATTERN = re.compile(r"(^\s*__REV__\s*=\s*)(\d+)(\s*$)", re.MULTILINE)
VERSION_PATTERN = re.compile(r"^\s*__VERSION__\s*=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)


def run_git(args):
    return subprocess.check_output(["git"] + args, text=True).strip()


def bump_revision(filename):
    path = Path(filename)
    text = path.read_text(encoding="utf-8")

    match = REV_PATTERN.search(text)
    if not match:
        raise RuntimeError(f"No __REV__ value found in {filename}")

    old_revision = int(match.group(2))
    new_revision = old_revision + 1

    text = REV_PATTERN.sub(
        lambda m: f"{m.group(1)}{new_revision}{m.group(3)}",
        text,
        count=1,
    )

    path.write_text(text, encoding="utf-8")
    return old_revision, new_revision


def get_version_string(filename):
    text = Path(filename).read_text(encoding="utf-8")

    match = VERSION_PATTERN.search(text)
    if not match:
        raise RuntimeError(f"No __VERSION__ value found in {filename}")

    return match.group(1)


def get_commits_for_file(since_ref, filename):
    output = run_git([
        "log",
        "--pretty=format:- %h %s",
        f"{since_ref}..HEAD",
        "--",
        filename,
    ])

    if not output:
        return "- No file-specific commits found."

    return output


def prepend_release_notes(release_notes_file, sections):
    path = Path(release_notes_file)

    old_text = ""
    if path.exists():
        old_text = path.read_text(encoding="utf-8")

    new_text = "\n\n".join(sections).rstrip() + "\n\n" + old_text
    path.write_text(new_text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True)
    parser.add_argument("--release-notes", required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--name", action="append", required=True)
    args = parser.parse_args()

    if len(args.file) != len(args.name):
        raise RuntimeError("Each --file needs a matching --name")

    sections = []

    for filename, name in zip(args.file, args.name):
        old_revision, new_revision = bump_revision(filename)
        version = get_version_string(filename)
        commits = get_commits_for_file(args.since, filename)

        section = f"[{name} {version}.{new_revision}]\n{commits}"
        sections.append(section)

        print(f"{filename}: __REV__ {old_revision} -> {new_revision}")

    prepend_release_notes(args.release_notes, sections)


if __name__ == "__main__":
    main()