import tempfile
import textwrap
import unittest
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import importlib.util

try:
    from datacrumbs_utils.probe_catalog import (  # type: ignore
        build_category_map,
        build_inventory,
        filter_catalog,
        prepare_runtime_config,
    )
    PROBE_CATALOG_AVAILABLE = True
except ImportError:
    PROBE_CATALOG_AVAILABLE = False

_CONFIGURE_TEMPLATES_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "python" / "configure_templates.py"
)
_CONFIGURE_TEMPLATES_SPEC = importlib.util.spec_from_file_location(
    "configure_templates", _CONFIGURE_TEMPLATES_PATH
)
if _CONFIGURE_TEMPLATES_SPEC is None or _CONFIGURE_TEMPLATES_SPEC.loader is None:
    raise RuntimeError(f"Unable to load configure_templates from {_CONFIGURE_TEMPLATES_PATH}")
_CONFIGURE_TEMPLATES_MODULE = importlib.util.module_from_spec(_CONFIGURE_TEMPLATES_SPEC)
_CONFIGURE_TEMPLATES_SPEC.loader.exec_module(_CONFIGURE_TEMPLATES_MODULE)
_expand_text = _CONFIGURE_TEMPLATES_MODULE._expand_text
_parse_defines = _CONFIGURE_TEMPLATES_MODULE._parse_defines
render_template = _CONFIGURE_TEMPLATES_MODULE.render_template


try:
    import yaml  # noqa: F401
except ImportError:
    YAML_AVAILABLE = False
else:
    YAML_AVAILABLE = True


@unittest.skipUnless(YAML_AVAILABLE, "PyYAML is required for inventory tests")
class ProbeCatalogTests(unittest.TestCase):
    def test_configure_templates_parses_define_overrides(self) -> None:
        merged = _parse_defines(
            [
                "DATACRUMBS_MPI_LIB=/usr/lib64/libmpi.so",
                "DATACRUMBS_CUSTOM_PROBE_BPF=/tmp/custom_probe.bpf.c",
            ]
        )
        self.assertEqual(merged["DATACRUMBS_MPI_LIB"], "/usr/lib64/libmpi.so")
        self.assertEqual(merged["DATACRUMBS_CUSTOM_PROBE_BPF"], "/tmp/custom_probe.bpf.c")

    def test_configure_templates_expands_template_variables(self) -> None:
        settings = {
            "DATACRUMBS_MPI_LIB": "/usr/lib64/libmpi.so",
            "DATACRUMBS_KERNEL_UNAME_R": "5.14.0-test",
            "DATACRUMBS_LIBC_SO": "/usr/lib64/libc.so.6",
        }

        template = textwrap.dedent(
            """
            capture_probes:
              - name: custom1
                file: @DATACRUMBS_MPI_LIB@
              - name: libc
                file: @DATACRUMBS_LIBC_SO@
              - name: sys
                file: @DATACRUMBS_KERNEL_HEADERS_PATH@/include/linux/syscalls.h
            """
        ).strip()

        expanded = _expand_text(template, settings)
        self.assertIn("/usr/lib64/libmpi.so", expanded)
        self.assertIn("/usr/lib64/libc.so.6", expanded)
        self.assertIn("@DATACRUMBS_KERNEL_HEADERS_PATH@/include/linux/syscalls.h", expanded)

    def test_configure_templates_renders_from_system_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            system_configuration_path = temp_path / "system-probe-test.sqlite"
            template_path = temp_path / "template.yaml"
            output_path = temp_path / "rendered.yaml"
            with sqlite3.connect(system_configuration_path) as connection:
                connection.execute(
                    "CREATE TABLE system_configuration (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute("CREATE TABLE summary (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.executemany(
                    "INSERT INTO system_configuration(key, value) VALUES (?, ?)",
                    [
                        ("DATACRUMBS_INSTALL_PREFIX", "/opt/datacrumbs"),
                        ("DATACRUMBS_INSTALL_HOST", "lead"),
                        ("DATACRUMBS_KERNEL_HEADERS_PATH", "/usr/src/kernels/5.14.0-test"),
                        ("DATACRUMBS_LIBC_SO", "/usr/lib64/libc.so.6"),
                    ],
                )
                connection.executemany(
                    "INSERT INTO summary(key, value) VALUES (?, ?)",
                    [
                        ("trace_log_dir", "/tmp/traces"),
                    ],
                )

            template_path.write_text(
                textwrap.dedent(
                    """
                    capture_probes:
                      - name: sys
                        file: @DATACRUMBS_KERNEL_HEADERS_PATH@/include/linux/syscalls.h
                      - name: libc
                        file: @DATACRUMBS_LIBC_SO@
                      - name: mpi
                        file: @DATACRUMBS_MPI_LIB@
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            settings = render_template(
                template_path=template_path,
                system_configuration_path=system_configuration_path,
                output_path=output_path,
                defines={"DATACRUMBS_MPI_LIB": "/usr/lib64/libmpi.so"},
            )

            rendered = output_path.read_text(encoding="utf-8")
            self.assertEqual(settings["DATACRUMBS_INSTALL_DIR"], "/opt/datacrumbs")
            self.assertIn("/usr/src/kernels/5.14.0-test/include/linux/syscalls.h", rendered)
            self.assertIn("/usr/lib64/libmpi.so", rendered)
            self.assertIn("/usr/lib64/libc.so.6", rendered)

    @unittest.skipUnless(PROBE_CATALOG_AVAILABLE, "probe_catalog module is unavailable")
    def test_inventory_merges_explored_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "lead.yaml"
            explored_path = temp_path / "explored.json"

            config_path.write_text(
                textwrap.dedent(
                    """
                    capture_probes:
                      - name: mpi
                        probe: uprobe
                        type: binary
                        file: /usr/lib64/libmpi.so
                        include_offsets: true
                      - name: custom1
                        probe: custom
                        type: custom
                        file: /tmp/custom.bpf.c
                        probes: /tmp/custom-probes.json
                        process_header: /tmp/custom.h
                        start_event_id: 100000
                        event_type: 2
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            explored_path.write_text(
                textwrap.dedent(
                    """
                    [
                      {
                        "name": "mpi",
                        "type": 2,
                        "functions": ["MPI_Init", "MPI_Finalize:0x18"]
                      }
                    ]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            inventory = build_inventory(str(config_path), str(explored_path))
            self.assertEqual(len(inventory["probes"]), 2)
            self.assertEqual(inventory["probes"][0]["functions"][0]["name"], "MPI_Init")
            self.assertEqual(inventory["probes"][0]["functions"][1]["name"], "MPI_Finalize:0x18")
            self.assertEqual(inventory["probes"][0]["functions"][0]["event_id"], 1000)
            self.assertEqual(inventory["probes"][0]["functions"][1]["event_id"], 1001)
            self.assertEqual(inventory["probes"][1]["start_event_id"], 100000)

            category_map = build_category_map(inventory)
            self.assertEqual(category_map["1000"]["probe_name"], "mpi")
            self.assertEqual(category_map["1001"]["function_name"], "MPI_Finalize:0x18")

    @unittest.skipUnless(PROBE_CATALOG_AVAILABLE, "probe_catalog module is unavailable")
    def test_query_filters_catalog(self) -> None:
        catalog = {
            "version": 1,
            "probes": [
                {
                    "name": "mpi",
                    "type": "uprobe",
                    "functions": [
                        {"name": "MPI_Init", "event_id": 1000},
                        {"name": "MPI_Finalize", "event_id": 1001},
                    ],
                },
                {
                    "name": "sched",
                    "type": "kprobe",
                    "functions": [{"name": "do_fork", "event_id": 1002}],
                },
            ],
        }

        filtered = filter_catalog(catalog, probe_names=["mpi"], probe_types=["uprobe"], function_regex="Init")
        self.assertEqual(len(filtered["probes"]), 1)
        self.assertEqual(filtered["probes"][0]["name"], "mpi")
        self.assertEqual(len(filtered["probes"][0]["functions"]), 1)
        self.assertEqual(filtered["probes"][0]["functions"][0]["name"], "MPI_Init")

    @unittest.skipUnless(PROBE_CATALOG_AVAILABLE, "probe_catalog module is unavailable")
    def test_prepare_runtime_config_writes_runtime_json_and_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "lead.yaml"
            explored_path = temp_path / "explored.json"
            runtime_root = temp_path / "runtime"
            runtime_json = temp_path / "out" / "runtime.json"
            env_file = temp_path / "out" / "service.env"

            config_path.write_text(
                textwrap.dedent(
                    """
                    capture_probes:
                      - name: mpi
                        probe: uprobe
                        type: binary
                        file: /usr/lib64/libmpi.so
                      - name: sys
                        probe: syscalls
                        type: header
                        file: /usr/include/linux/syscalls.h
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            explored_path.write_text(
                textwrap.dedent(
                    """
                    [
                      {
                        "name": "mpi",
                        "functions": ["MPI_Init", "MPI_Finalize"]
                      },
                      {
                        "name": "sys",
                        "functions": ["sys_openat2"]
                      }
                    ]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            payload = prepare_runtime_config(
                config_path=str(config_path),
                explored_path=str(explored_path),
                runtime_root=str(runtime_root),
                output_path=str(runtime_json),
                output_env_path=str(env_file),
                run_id="run-42",
                user="tester",
                hostname="lead",
                service_id="svc-42",
            )

            self.assertTrue((runtime_root / "logs").is_dir())
            self.assertTrue((runtime_root / "traces").is_dir())
            self.assertTrue((runtime_root / "run").is_dir())
            self.assertTrue((runtime_root / "data").is_dir())
            self.assertEqual(payload["run_id"], "run-42")
            self.assertEqual(payload["user"], "tester")
            self.assertEqual(payload["pid_file_path"], str(runtime_root / "run" / "svc-42.pid"))
            self.assertIn("category_map", payload)
            self.assertEqual(payload["category_map"]["1000"]["function_name"], "MPI_Init")
            self.assertTrue(runtime_json.exists())
            self.assertTrue(env_file.exists())
            self.assertIn("DATACRUMBS_CONFIG_JSON", env_file.read_text(encoding="utf-8"))

    @unittest.skipUnless(PROBE_CATALOG_AVAILABLE, "probe_catalog module is unavailable")
    def test_prepare_runtime_config_rewrites_legacy_catalog_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            runtime_root = temp_path / "runtime"
            runtime_json = temp_path / "out" / "runtime.json"
            catalog_path = temp_path / "catalog.json"

            catalog_path.write_text(
                textwrap.dedent(
                    """
                    {
                      "version": 1,
                      "probes": [
                        {
                          "name": "custom1",
                          "type": "custom",
                          "bpf_path": "@DATACRUMBS_PROJECT_PATH@/etc/datacrumbs/plugins/custom_probes/sys_io/sysio.bpf.c",
                          "process_header": "@DATACRUMBS_PROJECT_PATH@/etc/datacrumbs/plugins/custom_probes/sys_io/sysio_process.h",
                          "functions": [
                            {"name": "openat", "event_id": 100000}
                          ]
                        },
                        {
                          "name": "mpi",
                          "type": "uprobe",
                          "binary_path": "/tmp/datacrumbs/etc/datacrumbs/plugins/does-not-matter/libmpi.so",
                          "functions": [
                            {"name": "MPI_Init", "event_id": 1000}
                          ]
                        }
                      ]
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            payload = prepare_runtime_config(
                catalog_path=str(catalog_path),
                runtime_root=str(runtime_root),
                output_path=str(runtime_json),
                run_id="run-legacy",
                user="tester",
                hostname="lead",
                service_id="svc-legacy",
            )

            repo_root = Path(__file__).resolve().parents[1]
            probes = {probe["name"]: probe for probe in payload["probes"]}
            self.assertEqual(
                probes["custom1"]["bpf_path"],
                str(repo_root / "plugins" / "custom_probes" / "sys_io" / "sysio.bpf.c"),
            )
            self.assertEqual(
                probes["custom1"]["process_header"],
                str(repo_root / "plugins" / "custom_probes" / "sys_io" / "sysio_process.h"),
            )
            self.assertEqual(
                probes["mpi"]["binary_path"],
                str(repo_root / "plugins" / "does-not-matter" / "libmpi.so"),
            )
            self.assertEqual(payload["category_map"]["100000"]["function_name"], "openat")
            self.assertTrue(runtime_json.exists())

    @unittest.skipUnless(PROBE_CATALOG_AVAILABLE, "probe_catalog module is unavailable")
    def test_subset_cli_alias_filters_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "catalog.json"
            output_path = temp_path / "subset.json"

            input_path.write_text(
                textwrap.dedent(
                    """
                    {
                      "version": 1,
                      "probes": [
                        {
                          "name": "mpi",
                          "type": "uprobe",
                          "functions": [
                            {"name": "MPI_Init", "event_id": 1000},
                            {"name": "MPI_Finalize", "event_id": 1001}
                          ]
                        },
                        {
                          "name": "sys",
                          "type": "syscalls",
                          "functions": [
                            {"name": "openat2", "event_id": 1002}
                          ]
                        }
                      ]
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            repo_root = Path(__file__).resolve().parents[1]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(repo_root / "src")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "datacrumbs_utils.probe_catalog",
                    "subset",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--probe-name",
                    "mpi",
                    "--function-regex",
                    "Init",
                ],
                cwd=repo_root,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["probes"]), 1)
            self.assertEqual(payload["probes"][0]["name"], "mpi")
            self.assertEqual(len(payload["probes"][0]["functions"]), 1)
            self.assertEqual(payload["probes"][0]["functions"][0]["name"], "MPI_Init")


if __name__ == "__main__":
    unittest.main()
