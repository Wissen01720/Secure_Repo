"""Language detection by file name / extension."""

from __future__ import annotations

import os

EXTENSION_LANGUAGE = {
    ".py": "Python", ".pyw": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".vue": "Vue", ".svelte": "Svelte",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".groovy": "Groovy",
    ".gradle": "Gradle",
    ".cs": "C#", ".vb": "VB.NET", ".fs": "F#",
    ".php": "PHP", ".phtml": "PHP",
    ".go": "Go", ".rb": "Ruby", ".erb": "Ruby", ".rake": "Ruby", ".gemspec": "Ruby",
    ".rs": "Rust", ".swift": "Swift", ".dart": "Dart", ".lua": "Lua", ".pl": "Perl", ".pm": "Perl",
    ".r": "R", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".clj": "Clojure",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
    ".hxx": "C++", ".m": "Objective-C", ".mm": "Objective-C",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ksh": "Shell", ".fish": "Shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
    ".bat": "Batch", ".cmd": "Batch",
    ".tf": "Terraform", ".tfvars": "Terraform", ".hcl": "HCL",
    ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".jsonc": "JSON",
    ".xml": "XML", ".plist": "XML", ".csproj": "XML", ".fsproj": "XML", ".vbproj": "XML", ".props": "XML",
    ".config": "XML",
    ".html": "HTML", ".htm": "HTML", ".xhtml": "HTML", ".ejs": "HTML", ".hbs": "HTML",
    ".handlebars": "HTML", ".mustache": "HTML", ".j2": "HTML", ".jinja": "HTML", ".jinja2": "HTML",
    ".twig": "HTML", ".cshtml": "HTML", ".razor": "HTML", ".jsp": "HTML",
    ".css": "CSS", ".scss": "CSS", ".sass": "CSS", ".less": "CSS",
    ".sql": "SQL",
    ".md": "Markdown", ".markdown": "Markdown", ".rst": "reStructuredText", ".txt": "Text",
    ".ini": "INI", ".cfg": "INI", ".conf": "Config", ".cnf": "Config",
    ".properties": "Properties", ".env": "Env", ".toml": "TOML",
    ".sol": "Solidity",
}

FILENAME_LANGUAGE = {
    "dockerfile": "Dockerfile", "containerfile": "Dockerfile", "makefile": "Makefile",
    "gnumakefile": "Makefile", "jenkinsfile": "Groovy", "vagrantfile": "Ruby", "gemfile": "Ruby",
    "rakefile": "Ruby", "podfile": "Ruby", "procfile": "Config", "pipfile": "TOML",
    ".bashrc": "Shell", ".zshrc": "Shell", ".profile": "Shell", ".npmrc": "INI", ".pypirc": "INI",
    ".gitconfig": "INI", ".htaccess": "Config", ".netrc": "Config",
}

PROGRAMMING = {
    "Python", "JavaScript", "TypeScript", "Vue", "Svelte", "Java", "Kotlin", "Scala", "Groovy",
    "Gradle", "C#", "VB.NET", "F#", "PHP", "Go", "Ruby", "Rust", "Swift", "Dart", "Lua", "Perl",
    "R", "Elixir", "Erlang", "Clojure", "C", "C++", "Objective-C", "Shell", "PowerShell", "Batch",
    "Solidity",
}
CONFIG_LIKE = {"Env", "INI", "Config", "Properties", "YAML", "TOML"}
DOCUMENTATION = {"Markdown", "reStructuredText", "Text"}


def detect_language(rel_path: str) -> str:
    name = os.path.basename(rel_path)
    lower = name.lower()
    if lower in FILENAME_LANGUAGE:
        return FILENAME_LANGUAGE[lower]
    if lower.startswith("dockerfile") or lower.endswith(".dockerfile") or lower.startswith("containerfile"):
        return "Dockerfile"
    if lower == ".env" or lower.startswith(".env."):
        return "Env"
    _, ext = os.path.splitext(lower)
    return EXTENSION_LANGUAGE.get(ext, "Other")
