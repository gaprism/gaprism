"""The DCO check (scripts/check-dco.py): who must have signed off, and what the message says.

Each test builds a throw-away git repository, so that the check runs against real commits: signed
and unsigned ones, a sign-off by somebody else, merges and bots. No network is involved.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.helpers import PROJECT_ROOT

SCRIPT = PROJECT_ROOT / "scripts" / "check-dco.py"
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git is not installed")

ALICE = ("Alice Example", "alice@example.org")
BOB = ("Bob Example", "bob@example.org")
DEPENDABOT = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_dco", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_dco"] = module  # a dataclass looks its own module up
    spec.loader.exec_module(module)
    return module


check_dco = load_script()


class Repo:
    """A throw-away repository, kept apart from the developer's own git configuration."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "commit.gpgsign", "false")
        self.base = self.commit("the base", ALICE, signed=True)

    def git(self, *args: str, author: tuple[str, str] = ALICE) -> str:
        assert GIT is not None
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": author[0],
            "GIT_AUTHOR_EMAIL": author[1],
            "GIT_COMMITTER_NAME": author[0],
            "GIT_COMMITTER_EMAIL": author[1],
        }
        done = subprocess.run(
            [GIT, *args], cwd=self.path, env=env, capture_output=True, text=True, check=True
        )
        return done.stdout.strip()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")

    def commit(
        self,
        subject: str,
        author: tuple[str, str] = ALICE,
        *,
        signed: bool = False,
        signoff: str | None = None,
    ) -> str:
        """An empty commit. ``signed`` adds the author's sign-off, ``signoff`` a given line."""
        message = subject
        if signed:
            message += f"\n\nSigned-off-by: {author[0]} <{author[1]}>"
        if signoff:
            message += f"\n\nSigned-off-by: {signoff}"
        self.git("commit", "-q", "--allow-empty", "-m", message, author=author)
        return self.head()

    def reword(self, message: str) -> None:
        self.git("commit", "-q", "--allow-empty", "--amend", "-m", message)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Repo:
    config = tmp_path / "gitconfig"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))  # the script and the tests alike
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    made = Repo(tmp_path / "repo")
    monkeypatch.chdir(made.path)
    return made


def run(repo: Repo, capsys: pytest.CaptureFixture[str], head: str | None = None) -> tuple[int, str]:
    """The exit status and the output of the check over ``repo.base..head``."""
    status = check_dco.main([repo.base, head or repo.head()])
    captured = capsys.readouterr()
    return status, captured.out + captured.err


# ------------------------------------------------------------------------------ who must sign


def test_commits_signed_off_by_their_author_pass(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.commit("first", ALICE, signed=True)
    repo.commit("second", BOB, signed=True)
    status, output = run(repo, capsys)
    assert status == 0, output
    assert "2 commit(s) signed off" in output


def test_a_commit_without_a_sign_off_fails_and_the_message_says_how_to_fix_it(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    sha = repo.commit("add a thing", ALICE)
    status, output = run(repo, capsys)
    assert status == 1
    assert sha[:10] in output and "add a thing" in output and "no Signed-off-by line" in output
    assert "git commit --amend --no-edit -s" in output and "git rebase --signoff" in output
    assert "developercertificate.org" in output


def test_only_the_commits_that_are_wrong_are_listed(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.commit("good", ALICE, signed=True)
    bad = repo.commit("bad", BOB)
    repo.commit("also good", BOB, signed=True)
    status, output = run(repo, capsys)
    assert status == 1
    assert "1 of 3 commit(s)" in output
    listing = output.split("not signed off:")[1].split("How to fix")[0]
    assert bad[:10] in listing and "bad" in listing and "good" not in listing


def test_a_sign_off_by_somebody_else_does_not_count(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.commit("written by Bob", BOB, signoff="Alice Example <alice@example.org>")
    status, output = run(repo, capsys)
    assert status == 1
    assert "signed off by alice@example.org, not by its author bob@example.org" in output


def test_an_extra_sign_off_next_to_the_authors_is_fine(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.commit("patch passed on", BOB, signed=True, signoff="Alice Example <alice@example.org>")
    status, _ = run(repo, capsys)
    assert status == 0


def test_the_email_is_compared_without_regard_to_case(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.commit("mixed case", ALICE, signoff="Alice Example <Alice@Example.ORG>")
    status, _ = run(repo, capsys)
    assert status == 0


def test_the_key_of_the_line_is_not_case_sensitive_but_the_line_must_be_complete(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.commit("placeholder", ALICE)
    repo.reword("x\n\nsigned-off-by: A <alice@example.org>")
    assert run(repo, capsys)[0] == 0
    repo.reword("x\n\nSigned-off-by: Alice Example")
    assert run(repo, capsys)[0] == 1  # a name without an address certifies nothing


def test_a_sign_off_made_by_git_commit_s_is_accepted(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.git("commit", "-q", "--allow-empty", "-s", "-m", "signed by git itself", author=BOB)
    status, output = run(repo, capsys)
    assert status == 0, output


# ------------------------------------------------------------------------------ what is exempt


def test_commits_of_bots_are_exempt(repo: Repo, capsys: pytest.CaptureFixture[str]) -> None:
    repo.commit("bump a package", DEPENDABOT)
    repo.commit("a person's change", ALICE, signed=True)
    status, output = run(repo, capsys)
    assert status == 0, output
    assert "1 commit(s) signed off, 1 by bots (exempt)" in output


def test_merge_commits_are_not_checked_but_the_commits_they_bring_are(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    repo.git("checkout", "-q", "-b", "feature")
    brought = repo.commit("from the branch", BOB)  # not signed
    repo.git("checkout", "-q", "main")
    repo.commit("on main", ALICE, signed=True)
    repo.git("merge", "-q", "--no-ff", "-m", "Merge branch feature (unsigned merge)", "feature")
    status, output = run(repo, capsys)
    assert status == 1
    assert brought[:10] in output and "Merge branch" not in output


def test_what_the_base_already_has_is_not_checked(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pull request is judged on its own commits, not on the history it starts from."""
    repo.commit("old, unsigned work", ALICE)
    repo.base = repo.head()  # the base moves on
    repo.commit("the pull request's commit", BOB, signed=True)
    status, output = run(repo, capsys)
    assert status == 0, output
    assert "1 commit(s) signed off" in output


def test_an_empty_range_is_fine(repo: Repo, capsys: pytest.CaptureFixture[str]) -> None:
    status, output = run(repo, capsys, head=repo.base)
    assert status == 0 and "0 commit(s) signed off" in output


# ------------------------------------------------------------------------------ bad calls


@pytest.mark.parametrize(
    "args", [[], ["only-one"], ["a", "b", "c"], ["--all", "HEAD"], ["", "HEAD"]]
)
def test_wrong_arguments_are_refused_before_git_is_asked(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert check_dco.main(args) == 2
    assert "usage:" in capsys.readouterr().err


def test_an_unknown_revision_is_reported_with_the_hint_about_shallow_clones(
    repo: Repo, capsys: pytest.CaptureFixture[str]
) -> None:
    assert check_dco.main(["0" * 40, "1" * 40]) == 2
    assert "fetch-depth: 0" in capsys.readouterr().err


def test_the_script_runs_as_a_program_and_its_exit_status_is_the_answer(repo: Repo) -> None:
    def program(head: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), repo.base, head],
            cwd=repo.path,
            capture_output=True,
            text=True,
            check=False,
        )

    repo.commit("unsigned", ALICE)
    unsigned = program(repo.head())
    assert unsigned.returncode == 1 and "no Signed-off-by line" in unsigned.stdout
    repo.git("commit", "-q", "--allow-empty", "--amend", "-s", "--no-edit")
    signed = program(repo.head())
    assert signed.returncode == 0, signed.stdout + signed.stderr


# ------------------------------------------------------------------------------ the workflow


def test_ci_runs_the_check_on_pull_requests_with_the_whole_history() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = workflow[workflow.index("\n  dco:") :]
    assert "if: github.event_name == 'pull_request'" in job
    assert "fetch-depth: 0" in job  # the commits of the pull request must be there
    assert "scripts/check-dco.py" in job
    assert "github.event.pull_request.base.sha" in job
    assert "github.event.pull_request.head.sha" in job
    assert "contents: read" in workflow  # the job needs nothing more
