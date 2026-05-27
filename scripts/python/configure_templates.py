from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any


def _load_settings_from_environment() -> dict[str, str]:
    variables = {
        str(key): _stringify(value)
        for key, value in os.environ.items()
        if key.startswith("DATACRUMBS_")
    }

    install_prefix = variables.get("DATACRUMBS_INSTALL_PREFIX", "")
    if install_prefix and "DATACRUMBS_INSTALL_DIR" not in variables:
        variables["DATACRUMBS_INSTALL_DIR"] = install_prefix

    install_host = variables.get("DATACRUMBS_INSTALL_HOST", "")
    if install_host and "DATACRUMBS_HOST" not in variables:
        variables["DATACRUMBS_HOST"] = install_host

    scheduler = variables.get("DATACRUMBS_JOB_SCHEDULER", "")
    if scheduler and "DATACRUMBS_SCHEDULER_TYPE" not in variables:
        variables["DATACRUMBS_SCHEDULER_TYPE"] = scheduler

    job_id_var = variables.get("DATACRUMBS_JOB_ID_VAR", "")
    if job_id_var and "DATACRUMBS_SCHEDULER_JOBID_ENV_VAR" not in variables:
        variables["DATACRUMBS_SCHEDULER_JOBID_ENV_VAR"] = job_id_var

    inclusion_paths = variables.get("DATACRUMBS_INCLUSION_PATHS", "")
    if inclusion_paths and "DATACRUMBS_INCLUSION_PATH" not in variables:
        variables["DATACRUMBS_INCLUSION_PATH"] = inclusion_paths

    return variables


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _parse_defines(items: list[str]) -> dict[str, str]:
    defines: dict[str, str] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"Expected KEY=VALUE for --define, got: {item}")
        defines[key] = value
    return defines


def _validate_required_settings(settings: dict[str, str]) -> None:
    required_keys = (
        "DATACRUMBS_INSTALL_DIR",
        "DATACRUMBS_INSTALL_CONFIGS_DIR",
        "DATACRUMBS_INSTALL_DATA_DIR",
        "DATACRUMBS_INSTALL_USER",
        "DATACRUMBS_HOST",
    )
    missing = [key for key in required_keys if not settings.get(key)]
    if missing:
        raise ValueError(
            "Missing required DATACRUMBS_* environment settings: " + ", ".join(missing)
        )


def _expand_text(text: str, settings: dict[str, str]) -> str:
    expanded = text
    for key, value in settings.items():
        expanded = expanded.replace(f"@{key}@", value)
    return expanded


def render_template(template_path: Path, output_path: Path,
                    defines: dict[str, str] | None = None) -> dict[str, str]:
    settings = _load_settings_from_environment()
    if defines:
        settings.update(defines)
    _validate_required_settings(settings)

    template_text = template_path.read_text(encoding="utf-8")
    expanded = _expand_text(template_text, settings)

    remaining = re.findall(r"@[A-Za-z0-9_]+@", expanded)
    if remaining:
        unique = sorted(set(remaining))
        raise ValueError(
            f"Template '{template_path}' has unresolved placeholders: {', '.join(unique)}\n"
            "Set the corresponding DATACRUMBS_* environment variables before calling "
            "datacrumbs_configure_template."
        )

    # Detect file paths that collapsed to a bare root prefix because a path
    # variable was empty (e.g. "" + "/include/..." → "/include/...").
    bad_file_paths = re.findall(r"(?m)^\s*file:\s*(/(?:include|usr/include)/\S+)", expanded)
    if bad_file_paths:
        raise ValueError(
            f"Template '{template_path}' produced invalid file paths (path variable was empty): "
            + ", ".join(bad_file_paths)
            + "\nEnsure DATACRUMBS_KERNEL_HEADERS_PATH (or similar) is set and non-empty."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(expanded, encoding="utf-8")
    return settings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render one datacrumbs-utils YAML template using DATACRUMBS_* environment settings"
    )
    parser.add_argument("template", help="Input YAML template path")
    parser.add_argument("output", help="Rendered output YAML path")
    parser.add_argument(
        "--define",
        action="append",
        default=[],
        help="Additional template variable in KEY=VALUE form; may be repeated",
    )
    args = parser.parse_args()

    render_template(
        template_path=Path(args.template).resolve(),
        output_path=Path(args.output).resolve(),
        defines=_parse_defines(args.define),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
