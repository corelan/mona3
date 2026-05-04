#!/usr/bin/env python3
import argparse
import re
import subprocess
from pathlib import Path


AUTHOR_HANDLE_OVERRIDES = {
    "Peter Van Eeckhoutte": "corelanc0d3r",
}

REV_PATTERN = re.compile(r"(^\s*__REV__\s*=\s*)(\d+)(\s*$)", re.MULTILINE)
VERSION_PATTERN = re.compile(r"^\s*__VERSION__\s*=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)
GITHUB_NOREPLY_PATTERN = re.compile(
    r"^(?:\d+\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com$",
    re.IGNORECASE,
)


def run_git(args):
    return subprocess.check_output(["git"] + args, text=True).strip()


def get_commit_base_url():
    remote = run_git(["remote", "get-url", "origin"])
    remote = remote.strip()

    if remote.endswith(".git"):
        remote = remote[:-4]

    if remote.startswith("git@github.com:"):
        return f"https://github.com/{remote.split(':', 1)[1]}/commit"

    if remote.startswith("https://github.com/"):
        return f"{remote}/commit"

    raise RuntimeError(f"Unsupported origin remote for GitHub commit links: {remote}")


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
    commit_base_url = get_commit_base_url()
    output = run_git([
        "log",
        "--pretty=format:%an|||%ae|||%h %s",
        f"{since_ref}..HEAD",
        "--",
        filename,
    ])

    if not output:
        return "- No file-specific commits found."

    commits_by_author = {}

    for line in output.splitlines():
        author, email, msg = line.split("|||", 2)
        author = get_author_display(author, email)
        commits_by_author.setdefault(author, []).append(msg)

    result_lines = []

    for author in sorted(commits_by_author):
        result_lines.append(f"{author}:")
        for commit in commits_by_author[author]:
            short_sha, subject = commit.split(" ", 1)
            commit_url = f"{commit_base_url}/{short_sha}"
            result_lines.append(
                f"  - <link cmd=\"{commit_url}\">{short_sha}</link> {subject}"
            )

    return "\n".join(result_lines).strip()


def get_author_display(author_name, author_email):
    match = GITHUB_NOREPLY_PATTERN.match(author_email.strip())
    if match:
        return match.group(1)

    return AUTHOR_HANDLE_OVERRIDES.get(author_name, author_name)


def prepend_release_notes(release_notes_file, sections):
    path = Path(release_notes_file)

    old_text = ""
    if path.exists():
        old_text = path.read_text(encoding="utf-8")

    new_text = "\n\n".join(sections).rstrip() + "\n\n" + old_text
    path.write_text(new_text, encoding="utf-8")


def cleanup_old_release_notes(release_notes_file, latest_revisions, max_revision_distance=10):
    path = Path(release_notes_file)

    if not path.exists():
        return

    text = path.read_text(encoding="utf-8")

    header_pattern = re.compile(
        r"^\[(mona|windbglib)\s+(\d+\.\d+)\.(\d+)\]\s*$",
        re.MULTILINE,
    )

    matches = list(header_pattern.finditer(text))
    if not matches:
        return

    kept_sections = []

    for index, match in enumerate(matches):
        name = match.group(1)
        revision = int(match.group(3))

        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[start:end].strip()

        latest_revision = latest_revisions.get(name)

        if latest_revision is None:
            kept_sections.append(section)
            continue

        if latest_revision - revision <= max_revision_distance:
            kept_sections.append(section)

    path.write_text("\n\n".join(kept_sections).rstrip() + "\n", encoding="utf-8")


def build_commit_message(latest_revisions, prefix="Update revision", suffix=""):
    revision_parts = [
        f"{name}: {latest_revisions[name]}"
        for name in ("mona", "windbglib")
        if name in latest_revisions
    ]

    if not revision_parts:
        commit_message = prefix
    else:
        commit_message = f"{prefix} ({', '.join(revision_parts)})"

    suffix = suffix.strip()
    if suffix:
        commit_message = f"{commit_message} {suffix}"

    return commit_message


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True)
    parser.add_argument("--release-notes", required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--name", action="append", required=True)
    parser.add_argument("--commit-message-prefix", default="Update revision")
    parser.add_argument("--commit-message-suffix", default="")
    parser.add_argument("--github-output")
    args = parser.parse_args()

    if len(args.file) != len(args.name):
        raise RuntimeError("Each --file needs a matching --name")

    release_entries = []
    latest_revisions = {}

    for filename, name in zip(args.file, args.name):
        old_revision, new_revision = bump_revision(filename)
        version = get_version_string(filename)
        commits = get_commits_for_file(args.since, filename)

        latest_revisions[name] = new_revision
        release_entries.append((name, version, new_revision, commits))

        print(f"{filename}: __REV__ {old_revision} -> {new_revision}")

    commit_message = build_commit_message(
        latest_revisions,
        prefix=args.commit_message_prefix,
        suffix=args.commit_message_suffix,
    )

    sections = []
    for name, version, new_revision, commits in release_entries:
        section = f"[{name} {version}.{new_revision}]\n- {commit_message}\n{commits}"
        sections.append(section)

    prepend_release_notes(args.release_notes, sections)

    cleanup_old_release_notes(
        args.release_notes,
        latest_revisions,
        max_revision_distance=10,
    )

    print(f"Commit message: {commit_message}")

    if args.github_output:
        github_output = Path(args.github_output)
        with github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"commit_message={commit_message}\n")


if __name__ == "__main__":
    main()
