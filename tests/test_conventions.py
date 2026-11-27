import ast
import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINT_DIRECTIVE = re.compile(r"#\s*(noqa(:\s*[A-Z]+[0-9]+(,\s*[A-Z]+[0-9]+)*)?|type:\s*ignore(\[[\w-]+(,\s*[\w-]+)*\])?|pragma:\s*no cover)\s*$")
DOCUMENTED = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def violations(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    found = [(token.start[0], f"comment {token.string!r}")
             for token in tokenize.generate_tokens(io.StringIO(source).readline)
             if token.type == tokenize.COMMENT and not LINT_DIRECTIVE.fullmatch(token.string)
             and not (token.start == (1, 0) and token.string.startswith("#!"))]
    found += [(node.body[0].lineno, f"docstring of {getattr(node, 'name', 'the module')}")
              for node in ast.walk(ast.parse(source))
              if isinstance(node, DOCUMENTED) and ast.get_docstring(node) is not None]
    return [f"{path}:{line}: {what}" for line, what in sorted(found)]


def checked_files() -> list[Path]:
    return sorted((ROOT / "keyfence").glob("*.py")) + sorted((ROOT / "plugin" / "hooks").glob("*.py"))


def test_the_code_holds_no_comments_and_no_docstrings():
    assert checked_files()
    found = [line for path in checked_files() for line in violations(path)]
    assert not found, "docs/development.md: no comments or docstrings in code\n" + "\n".join(found)


def test_the_checker_reports_a_comment_and_a_docstring_with_their_lines(tmp_path):
    module = tmp_path / "module.py"
    module.write_text('def f():\n    """Explain f."""\n    return 1  # why\n')
    assert violations(module) == [
        f"{module}:2: docstring of f",
        f"{module}:3: comment '# why'",
    ]


def test_the_checker_allows_a_bare_lint_directive(tmp_path):
    module = tmp_path / "module.py"
    module.write_text("import os  # noqa: E402\nimport sys  # noqa\nx = 1  # type: ignore\n"
                      "y = 2  # type: ignore[attr-defined, no-any-return]\nz = 3  # pragma: no cover\n")
    assert violations(module) == []


def test_the_checker_rejects_a_lint_directive_that_carries_a_comment(tmp_path):
    module = tmp_path / "module.py"
    module.write_text("import os  # noqa: E402 because the path is set first\n"
                      "x = f()  # type: ignore[because the stub is wrong]\n")
    assert violations(module) == [
        f"{module}:1: comment '# noqa: E402 because the path is set first'",
        f"{module}:2: comment '# type: ignore[because the stub is wrong]'",
    ]


def test_the_checker_ignores_a_hash_inside_a_string(tmp_path):
    module = tmp_path / "module.py"
    module.write_text('PATTERN = "#[0-9]+"\n')
    assert violations(module) == []


def test_the_checker_allows_a_shebang_on_the_first_line_only(tmp_path):
    module = tmp_path / "module.py"
    module.write_text("#!/usr/bin/env python3\nx = 1\n#!not a shebang\n")
    assert violations(module) == [f"{module}:3: comment '#!not a shebang'"]
