"""Check that every commit of a pull request is signed off (Developer Certificate of Origin 1.1).

    python scripts/check-dco.py BASE HEAD

BASE and HEAD are commits: CI passes the SHAs of the pull request's base and head. The commits
reachable from HEAD and not from BASE are checked, merge commits aside. Each one needs a
``Signed-off-by: Name <email>`` line whose email is the author's; commits of bots (Dependabot,
GitHub Actions) are exempt, because a bot cannot certify anything.

Exit status: 0 when every commit is signed off, 1 when one is not, 2 when the arguments or git did
not work. Standard library only, so that the CI job needs nothing installed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass

SIGN_OFF = re.compile(
    r"^signed-off-by:\s*(?P<name>.*?)\s*<(?P<email>[^<>\s]+)>\s*$", re.IGNORECASE | re.MULTILINE
)
BOT = re.compile(r"\[bot\]", re.IGNORECASE)  # dependabot[bot], github-actions[bot], ...
REF = re.compile(r"[0-9A-Za-z][0-9A-Za-z._/~^@{}-]*")  # a revision, never something like "--all"
FIELD, RECORD = "\x1f", "\x1e"

HOW_TO_FIX = """\
How to fix it: add the line with `git commit -s`. For commits that exist already:

    git commit --amend --no-edit -s     # the last commit only
    git rebase --signoff {base}         # every commit of the branch
    git push --force-with-lease

A sign-off says that you wrote the change or have the right to submit it under the project's
licence (https://developercertificate.org/). CONTRIBUTING.md has the details."""


class GitError(Exception):
    """Git is missing, or it refused the question."""


@dataclass(frozen=True)
class Commit:
    sha: str
    author_name: str
    author_email: str
    message: str

    @property
    def subject(self) -> str:
        return self.message.strip().splitlines()[0] if self.message.strip() else ""

    @property
    def is_bot(self) -> bool:
        return bool(BOT.search(self.author_name) or BOT.search(self.author_email))

    @property
    def signed_off_by(self) -> list[str]:
        """The email addresses of the sign-off lines, lower case."""
        return [found.group("email").lower() for found in SIGN_OFF.finditer(self.message)]


def git(*args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise GitError("git is not installed")
    # Fixed subcommands; the only outside input is the two revisions, which main() has validated.
    result = subprocess.run(  # noqa: S603
        [executable, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or f"git {args[0]} failed")
    return result.stdout


def commits_between(base: str, head: str) -> list[Commit]:
    """The non-merge commits reachable from ``head`` and not from ``base``, oldest first."""
    log = git(
        "log",
        "--no-merges",
        "--reverse",
        f"--format=%H{FIELD}%an{FIELD}%ae{FIELD}%B{RECORD}",
        f"{base}..{head}",
        "--",
    )
    commits = []
    for record in log.split(RECORD):
        if not record.strip():
            continue
        sha, name, email, message = record.lstrip("\n").split(FIELD, 3)
        commits.append(Commit(sha, name, email, message))
    return commits


def problems(commits: Sequence[Commit]) -> list[tuple[Commit, str]]:
    """The commits that are not signed off by their author, each with what is wrong."""
    found = []
    for commit in commits:
        if commit.is_bot:
            continue
        signed = commit.signed_off_by
        if commit.author_email.lower() in signed:
            continue
        if signed:
            reason = f"signed off by {', '.join(signed)}, not by its author {commit.author_email}"
        else:
            reason = "no Signed-off-by line"
        found.append((commit, reason))
    return found


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or not all(REF.fullmatch(arg) for arg in args):
        print(
            "usage: check-dco.py BASE HEAD (two commits, for example the SHAs of a PR)",
            file=sys.stderr,
        )
        return 2
    base, head = args
    try:
        commits = commits_between(base, head)
    except GitError as error:
        print(
            f"git could not list the commits: {error}\n"
            "(a shallow clone lacks them: check out with fetch-depth: 0)",
            file=sys.stderr,
        )
        return 2

    wrong = problems(commits)
    checked = sum(1 for commit in commits if not commit.is_bot)
    if not wrong:
        print(f"DCO: {checked} commit(s) signed off, {len(commits) - checked} by bots (exempt).")
        return 0
    print(f"DCO: {len(wrong)} of {len(commits)} commit(s) are not signed off:\n")
    for commit, reason in wrong:
        print(f"  {commit.sha[:10]}  {commit.subject[:70]}\n              {reason}")
    print("\n" + HOW_TO_FIX.format(base=base[:10] if len(base) > 10 else base))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
