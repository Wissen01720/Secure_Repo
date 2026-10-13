"""One sample per supported manifest / lockfile format, plus hostile and malformed inputs (C-38)."""
import json

import pytest

from secure_repo.core import deps

CARGO_LOCK = ('[[package]]\nname = "serde"\nversion = "1.0.100"\nsource = "registry+https://github.com/rust-lang/'
              'crates.io-index"\n\n[[package]]\nname = "my-crate"\nversion = "0.1.0"\n')

SAMPLES = {
    "requirements.txt": ("flask==2.0.1\nrequests>=2.0  # comment\n-r other.txt\n# c\ndjango[argon2]==4.2 ; python_version>'3.8'\n",
                         {("flask", "2.0.1"), ("requests", None), ("django", "4.2")}),
    "requirements/prod.txt": ("flask==2.0.1\n", {("flask", "2.0.1")}),
    "dev-requirements.in": ("pytest>=7\n", {("pytest", None)}),
    "pyproject.toml": ('[project]\nname="x"\ndependencies=["rich>=13", "tomli==2.0.1"]\n'
                       '[project.optional-dependencies]\ndev=["pytest>=7"]\n[tool.poetry.dependencies]\npython="^3.9"\nattrs="^23.1"\n',
                       {("rich", None), ("tomli", "2.0.1"), ("pytest", None), ("attrs", None)}),
    "Pipfile": ('[packages]\nflask = "==2.0.1"\nrequests = "*"\n[dev-packages]\npytest = "*"\n',
                {("flask", "2.0.1"), ("requests", None), ("pytest", None)}),
    "Pipfile.lock": (json.dumps({"default": {"flask": {"version": "==2.0.1"}}, "develop": {"pytest": {"version": "==7.0.0"}}}),
                     {("flask", "2.0.1"), ("pytest", "7.0.0")}),
    "poetry.lock": ('[[package]]\nname = "attrs"\nversion = "23.1.0"\n\n[[package]]\nname = "idna"\nversion = "3.4"\n',
                    {("attrs", "23.1.0"), ("idna", "3.4")}),
    "uv.lock": ('[[package]]\nname = "attrs"\nversion = "23.1.0"\n\n[[package]]\nname = "me"\nversion = "1"\n'
                'source = { editable = "." }\n', {("attrs", "23.1.0")}),
    "setup.py": ("from setuptools import setup\nsetup(name='x', install_requires=['flask==2.0.1', 'requests>=2'])\n",
                 {("flask", "2.0.1"), ("requests", None)}),
    "setup.cfg": ("[options]\ninstall_requires =\n    flask==2.0.1\n    requests>=2\n", {("flask", "2.0.1"), ("requests", None)}),
    "package.json": (json.dumps({"dependencies": {"express": "4.17.1", "left-pad": "^1.3.0", "local": "file:../local"},
                                 "devDependencies": {"jest": "~29.0.0"}}),
                     {("express", "4.17.1"), ("left-pad", None), ("jest", None), ("local", None)}),
    "package-lock.json": (json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "x"},
                                                                          "node_modules/express": {"version": "4.17.1"}}}),
                          {("express", "4.17.1")}),
    "yarn.lock": ('# yarn lockfile v1\n\nexpress@^4.17.1:\n  version "4.17.1"\n  resolved "https://x"\n', {("express", "4.17.1")}),
    "pnpm-lock.yaml": ("lockfileVersion: '6.0'\npackages:\n  /express@4.17.1:\n    resolution: {integrity: sha512-x}\n",
                       {("express", "4.17.1")}),
    "go.mod": ("module x\n\ngo 1.20\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/text v0.3.7 // indirect\n)\n",
               {("github.com/gin-gonic/gin", "1.9.0"), ("golang.org/x/text", "0.3.7")}),
    "Cargo.toml": ('[package]\nname="x"\n[dependencies]\nserde = "1.0"\ntokio = { version = "1.0", features = ["full"] }\n',
                   {("serde", None), ("tokio", None)}),
    "Cargo.lock": (CARGO_LOCK, {("serde", "1.0.100")}),                 # workspace members have no source and are skipped
    "Gemfile": ("source 'https://rubygems.org'\ngem 'rails', '~> 6.0'\ngem 'puma'\n", {("rails", None), ("puma", None)}),
    "Gemfile.lock": ("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.0.3)\n      actionpack (= 6.0.3)\n\nPLATFORMS\n  ruby\n",
                     {("rails", "6.0.3")}),
    "composer.json": (json.dumps({"require": {"php": ">=7.4", "monolog/monolog": "^2.0"}, "require-dev": {"phpunit/phpunit": "^9"}}),
                      {("monolog/monolog", None), ("phpunit/phpunit", None)}),
    "composer.lock": (json.dumps({"packages": [{"name": "monolog/monolog", "version": "2.0.0"}], "packages-dev": []}),
                      {("monolog/monolog", "2.0.0")}),
    "pubspec.yaml": ("name: x\ndependencies:\n  http: ^0.13.0\n  flutter:\n    sdk: flutter\ndev_dependencies:\n  test: ^1.0.0\n",
                     {("http", None), ("test", None)}),
    "pubspec.lock": ('packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n'
                     '    source: hosted\n    version: "0.13.0"\n', {("http", "0.13.0")}),
    "pom.xml": ("<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
                "<version>2.14.1</version></dependency></dependencies></project>",
                {("org.apache.logging.log4j:log4j-core", "2.14.1")}),
    "build.gradle": ("dependencies {\n    implementation 'com.google.guava:guava:31.0-jre'\n    testImplementation(\"junit:junit:4.13\")\n}\n",
                     {("com.google.guava:guava", "31.0-jre"), ("junit:junit", "4.13")}),
    "build.gradle.kts": ('dependencies {\n    implementation("com.google.guava:guava:31.0-jre")\n}\n',
                         {("com.google.guava:guava", "31.0-jre")}),
    "libs.versions.toml": ('[versions]\nguava = "31.0-jre"\n[libraries]\nguava = { module = "com.google.guava:guava", version.ref = "guava" }\n',
                           {("com.google.guava:guava", "31.0-jre")}),
    "App.csproj": ('<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>',
                   {("Newtonsoft.Json", "12.0.1")}),
    "packages.config": ('<packages><package id="Newtonsoft.Json" version="12.0.1" targetFramework="net48" /></packages>',
                        {("Newtonsoft.Json", "12.0.1")}),
    "packages.lock.json": (json.dumps({"version": 1, "dependencies": {"net6.0": {"Newtonsoft.Json": {"type": "Direct",
                                                                                                   "resolved": "12.0.1"}}}}),
                           {("Newtonsoft.Json", "12.0.1")}),
}


def parse(name, text):
    parser, is_lock = deps.parser_for(name)
    issues = []
    return parser(text, name, issues), is_lock, issues


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_every_format_yields_the_expected_dependencies(name):
    text, expected = SAMPLES[name]
    found, _is_lock, _issues = parse(name, text)
    assert {(d.name, d.version) for d in found} >= expected, [(d.name, d.version) for d in found]


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_lockfile_flag_matches_the_file_kind(name):
    _found, is_lock, _issues = parse(name, SAMPLES[name][0])
    assert is_lock == deps.is_lockfile(name)
    assert deps.is_manifest(name)


HOSTILE = ["", "\x00\x01\x02", "{{{{[[[[<<<<", '{"dependencies": ', "<project><dependencies><dependency>", "[[package]\nname=",
           "a" * 50000, "{" * 2000, '{"dependencies": {"x": ' + "[" * 500 + "}}", "﻿# only a bom"]


@pytest.mark.parametrize("name", sorted(SAMPLES))
@pytest.mark.parametrize("text", HOSTILE, ids=[f"hostile{i}" for i in range(len(HOSTILE))])
def test_malformed_files_never_crash_a_parser(name, text):
    found, _is_lock, _issues = parse(name, text)
    assert isinstance(found, list)


INSECURE = {
    "requirements.txt": "--index-url http://mirror.example.org/simple\nflask==2.0\n--trusted-host mirror.example.org\n",
    "package.json": json.dumps({"dependencies": {"evil": "http://example.org/evil.tgz"}}),
    "Gemfile": "source 'http://rubygems.org'\ngem 'rails'\n",
    "composer.json": json.dumps({"repositories": [{"type": "composer", "url": "http://repo.example.org"}], "require": {}}),
    "pom.xml": "<project><repositories><repository><url>http://repo.example.org/maven</url></repository></repositories></project>",
}


@pytest.mark.parametrize("name", sorted(INSECURE))
def test_insecure_package_sources_are_reported(name):
    _found, _lock, issues = parse(name, INSECURE[name])
    assert issues and all(issue.rule_id == "SR-DEP-006" for issue in issues), name


def test_unknown_files_have_no_parser():
    assert deps.parser_for("README.md") is None and not deps.is_manifest("src/app.py")


def test_xml_entity_bombs_are_not_expanded():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            '<project><dependencies><dependency><groupId>&b;</groupId><artifactId>x</artifactId><version>1</version>'
            '</dependency></dependencies></project>')
    found, _lock, _issues = parse("pom.xml", bomb)
    assert all("aaaaaaaaaa" not in d.name for d in found)


def test_normalize_name_follows_each_ecosystem_rules():
    assert deps.normalize_name("PyPI", "Flask_RESTful.ext") == "flask-restful-ext"
    assert deps.normalize_name("npm", "Express") == "Express" or deps.normalize_name("npm", "Express") == "express"


# ---- a damaged manifest must not look like "no dependencies" -------------------------------------------------
BROKEN = {
    "package.json": '{"dependencies": {"express": ',
    "composer.lock": '{"packages": [',
    "pyproject.toml": "[project\nname=",
    "Cargo.toml": 'name = = "x"',
    "pom.xml": "<project><dependencies><dependency>",
    "App.csproj": "<Project><ItemGroup>",
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_syntax_errors_are_detected_for_strict_formats(name):
    assert deps.syntax_error(name, BROKEN[name])


@pytest.mark.parametrize("name", sorted(n for n in SAMPLES if n in ("package.json", "composer.lock", "pyproject.toml",
                                                                    "Cargo.toml", "pom.xml", "App.csproj", "Pipfile.lock",
                                                                    "poetry.lock", "packages.config", "libs.versions.toml")))
def test_valid_samples_have_no_syntax_error(name):
    assert deps.syntax_error(name, SAMPLES[name][0]) is None


def test_lenient_and_empty_files_are_not_flagged():
    assert deps.syntax_error("requirements.txt", "this is ((not a requirement") is None
    assert deps.syntax_error("package.json", "   \n") is None
    assert deps.syntax_error("README.md", "{") is None


def test_the_report_lists_manifests_that_could_not_be_parsed(tmp_path):
    from secure_repo.core.events import EventBus
    from secure_repo.core.scanner import Scanner, ScanOptions
    from secure_repo.core.workspace import Target
    from secure_repo.report import formats
    from tests.conftest import write

    root = str(tmp_path / "r")
    write(root, "package.json", BROKEN["package.json"])
    write(root, "services/api/pom.xml", BROKEN["pom.xml"])
    write(root, "requirements.txt", "flask==2.0.1\n")
    report, _ = Scanner(ScanOptions(offline=True, trust_repo_config=True), EventBus()).run(Target.parse(root),
                                                                                            write_reports=False)
    unparsed = {item["path"]: item["error"] for item in report["analysis"]["not_analyzed"]["unparsed"]}
    assert set(unparsed) == {"package.json", "services/api/pom.xml"} and "JSON" in unparsed["package.json"]
    assert any(d["name"] == "flask" for d in report["dependencies"])
    markdown = formats.markdown_quality(report)
    assert "could not be parsed" in markdown and "services/api/pom.xml" in markdown
