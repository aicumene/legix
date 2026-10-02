#!/usr/bin/env python3
"""Rename the gitoxide workspace to legix: packages, libraries, crate directories and code paths.

leGix is a fork of gitoxide (https://github.com/GitoxideLabs/gitoxide). To take a new upstream
release, check out its tag, run this script from the repository root on the clean tree, then
re-apply the leGix commits on top. The script only renames; it changes no behaviour.

What it renames
- packages: gix -> legix, gix-* -> legix-*, gix-testtools -> legix-testtools,
  gitoxide-core -> legix-core, gitoxide (the CLI package) -> legix-cli;
- libraries in code: gix -> legix, gix_* -> legix_*, gitoxide_core -> legix_core;
- crate directories: gix/ -> legix/, gix-*/ -> legix-*/, gitoxide-core/ -> legix-core/;
- the plumbing binary gix -> legix (the porcelain binary ein keeps its name).

What it leaves alone, on purpose
- the git configuration section `gitoxide.*` and the `config::tree::gitoxide` module: users'
  git configuration names these keys;
- environment variables (GIX_*), the user agent and other wire-visible strings;
- test data and fixture scripts: expected outputs quote paths from gitoxide's own history, and
  the fixture archives are keyed on the scripts' content;
- CHANGELOG files: they record upstream releases under their original names.
"""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def members():
    for member in tomllib.load(open(ROOT / "Cargo.toml", "rb"))["workspace"]["members"]:
        manifest = tomllib.load(open(ROOT / member / "Cargo.toml", "rb"))
        package = manifest["package"]["name"]
        lib = (manifest.get("lib") or {}).get("name") or package.replace("-", "_")
        yield member, package, lib


def new_package(name):
    if name == "gitoxide":
        return "legix-cli"
    if name == "gitoxide-core":
        return "legix-core"
    if name == "gix" or name.startswith("gix-"):
        return "le" + name
    return name


def new_lib(name):
    if name == "gitoxide_core":
        return "legix_core"
    if name == "gix" or name.startswith("gix_"):
        return "le" + name
    return name


MEMBERS = list(members())
PACKAGES = {p: new_package(p) for _, p, _ in MEMBERS if new_package(p) != p}
LIBS = {l: new_lib(l) for _, _, l in MEMBERS if new_lib(l) != l}
DIRS = {m: new_package(p) for m, p, _ in MEMBERS if m == p and new_package(p) != p}

HYPHENATED = re.compile(r"(?<![A-Za-z0-9_-])(gix(?:-[a-z0-9]+)+|gitoxide-core)(?![A-Za-z0-9_-])")
UNDERSCORED = re.compile(r"(?<![A-Za-z0-9_])(gix_[a-z0-9_]+|gitoxide_core)(?![A-Za-z0-9_])")


def hyphenated(text):
    return HYPHENATED.sub(lambda m: PACKAGES.get(m.group(1), m.group(1)), text)


def underscored(text):
    return UNDERSCORED.sub(lambda m: LIBS.get(m.group(1), m.group(1)), text)


SOURCE_LOCATION = re.compile(r"(?<![A-Za-z0-9_/.-])(gix(?:-[a-z0-9]+)*)/((?:src|tests|examples|benches)/[^\s\"':]+\.rs:\d+)")


def source_locations(text):
    """`gix-error/tests/error/main.rs:26` in expected output is this workspace's own source file, which
    moved with its crate. Paths without a line number may be data from gitoxide's history and stay."""
    return SOURCE_LOCATION.sub(lambda m: f"{DIRS.get(m.group(1), m.group(1))}/{m.group(2)}", text)


def cargo_manifest(text, is_root):
    text = hyphenated(underscored(text))
    # The bare `gix` package: as a dependency key or section, a feature path, a crate directory,
    # a name or a docs.rs link — never inside file paths such as "src/gix.rs".
    text = re.sub(r'(?m)^(\s*)gix(\s*=)', r"\1legix\2", text)
    text = re.sub(r'(?m)^\[((?:dev-|build-)?dependencies|target\.[^\]]+\.(?:dev-|build-)?dependencies)\.gix\]',
                  r"[\1.legix]", text)
    text = re.sub(r'"(dep:)?gix(\??/)', r'"\1legix\2', text)
    text = re.sub(r'"(dep:)?gix"', r'"\1legix"', text)
    text = re.sub(r'(\.\./)+gix"', lambda m: m.group(0)[:-4] + 'legix"', text)
    text = text.replace("https://docs.rs/gix\"", "https://docs.rs/legix\"")
    text = text.replace("https://github.com/GitoxideLabs/gitoxide", "https://github.com/aicumene/legix")
    text = text.replace("A crate of the gitoxide project", "A crate of legix, a fork of the gitoxide project")
    if is_root:
        text = re.sub(r'(?m)^name = "gitoxide"$', 'name = "legix-cli"', text)
    return text


def rust_source(text, path):
    text = underscored(text)
    text = re.sub(r"(?<![A-Za-z0-9_:])gix::", "legix::", text)
    text = re.sub(r"(?<![A-Za-z0-9_])::gix::", "::legix::", text)
    text = re.sub(r"(?<![A-Za-z0-9_])(extern crate|use) gix(?=\s*(?:;|\bas\b))", r"\1 legix", text)
    # Aliases of the crate under test, e.g. `use crate as gix;` in the legix crate's unit tests.
    text = re.sub(r"(?<![A-Za-z0-9_])as gix(?=\s*;)", "as legix", text)
    # Paths into a sibling crate's directory, e.g. "../gix-odb/tests/fixtures".
    text = re.sub(r"(?<=\.\./)(gix(?:-[a-z0-9]+)+)(?=/)", lambda m: PACKAGES.get(m.group(1), m.group(1)), text)
    # Package names handed to cargo by tests: `"-p", "gix-prompt"`, `.arg("-p").arg("gix-imara-diff")`
    # and `build_example_for_test("gix-filter", ...)`.
    text = re.sub(r'((?:"(?:-p|--package)"\s*,|\.arg\("(?:-p|--package)"\)\s*\.arg\(|build_example_for_test\()\s*")'
                  r'(gix(?:-[a-z0-9]+)*)(")', lambda m: m.group(1) + PACKAGES.get(m.group(2), m.group(2)) + m.group(3), text)
    text = source_locations(text)
    # Documentation comments name the crates; string literals (test data) are left alone.
    text = re.sub(r"(?m)^(\s*//[/!]?.*)$", lambda m: hyphenated(m.group(1)), text)
    if path in ("src/gix.rs", "src/ein.rs"):
        # The binaries call the CLI package's own library, named after the package.
        text = re.sub(r"(?<![A-Za-z0-9_:])gitoxide::", "legix_cli::", text)
    if path == "src/plumbing/options/mod.rs":
        text = text.replace('#[clap(name = "gix",', '#[clap(name = "legix",')
    if path == "tests/tools/src/repository/mod.rs":
        text = text.replace("\nmod gix;\n", "\nmod legix;\n")
    return text


def dev_script(text):
    """justfile, Makefile and maintenance scripts: everything there names crates, directories or the binary."""
    text = hyphenated(underscored(text))
    text = re.sub(r"\b(debug|release)/gix(?![A-Za-z0-9_.-])", r"\1/legix", text)
    return re.sub(r"(?<![A-Za-z0-9_./-])gix(?![A-Za-z0-9_-])", "legix", text)


def main():
    dirty = [line for line in git("status", "--porcelain").splitlines() if not line.endswith("etc/legix-rename.py")]
    if dirty:
        sys.exit("the tree is not clean; run on a fresh checkout of an upstream release")
    for old, new in DIRS.items():
        git("mv", old, new)
    git("mv", "tests/tools/src/repository/gix.rs", "tests/tools/src/repository/legix.rs")

    # insta names snapshots of unit tests after the library: gix_tix__edit__...snap.
    for path in git("ls-files", "*.snap").splitlines():
        name = Path(path).name
        lib = name.split("__", 1)[0]
        if "__" in name and lib in LIBS:
            git("mv", path, str(Path(path).with_name(LIBS[lib] + name[len(lib):])))

    changed = 0
    for path in git("ls-files").splitlines():
        file = ROOT / path
        parts = Path(path).parts
        if "fixtures" in parts or path.endswith("CHANGELOG.md") or not file.is_file():
            continue
        if path.endswith("Cargo.toml"):
            convert = lambda t: cargo_manifest(t, path == "Cargo.toml")
        elif path.endswith(".rs"):
            convert = lambda t: rust_source(t, path)
        elif path.endswith(".snap"):
            convert = lambda t: source_locations(re.sub(r"(?m)^source: (gix(?:-[a-z0-9]+)*)/",
                                                        lambda m: f"source: {DIRS.get(m.group(1), m.group(1))}/", t))
        elif path in ("justfile", "Makefile", "deny.toml", "_typos.toml") or path.startswith("etc/") \
                or (path.startswith(tuple(f"{d}/fuzz/" for d in DIRS.values())) and path.endswith(".sh")):
            if path == "etc/legix-rename.py":
                continue
            convert = dev_script
        else:
            continue
        try:
            text = file.read_text()
        except UnicodeDecodeError:
            continue
        new = convert(text)
        if new != text:
            file.write_text(new)
            changed += 1
    print(f"renamed {len(DIRS)} directories, {len(PACKAGES)} packages, {len(LIBS)} libraries; "
          f"rewrote {changed} files")


if __name__ == "__main__":
    main()
