import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "axdemo.py"
SPEC = importlib.util.spec_from_file_location("axdemo", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PathTests(unittest.TestCase):
    def test_default_logs_dir_is_docs_logs(self) -> None:
        self.assertEqual(MODULE.DEFAULT_LOGS_DIR, MODULE.ROOT / "docs" / "ebpf-tracing" / "logs")

    def test_run_layout_is_nested_under_run_id(self) -> None:
        paths = MODULE.make_run_layout("20260419-010203")
        self.assertEqual(paths["log_dir"], MODULE.DEFAULT_LOGS_DIR / "20260419-010203")
        self.assertEqual(paths["raw_log"], paths["log_dir"] / "axebpf-mainline-integration.raw.log")
        self.assertEqual(paths["clean_log"], paths["log_dir"] / "axebpf-mainline-integration.clean.log")
        self.assertEqual(paths["summary"], paths["log_dir"] / "summary.txt")


class CliTests(unittest.TestCase):
    def test_parse_args_defaults(self) -> None:
        args = MODULE.parse_args([])
        self.assertFalse(args.skip_build_axvisor)
        self.assertFalse(args.keep_workdir)
        self.assertEqual(args.axvisor_guest_ref, MODULE.DEFAULT_AXVISOR_GUEST_REF)
        self.assertEqual(args.logs_dir, MODULE.DEFAULT_LOGS_DIR)
        self.assertFalse(args.reuse_axvisor_guest_clone)

    def test_collect_missing_requirements_reports_missing_binary_and_module(self) -> None:
        missing = MODULE.collect_missing_requirements(
            which=lambda _: None,
            import_checker=lambda _: False,
        )
        self.assertIn("git", missing)
        self.assertIn("pexpect", missing)


class WorkspaceTests(unittest.TestCase):
    def test_prepare_run_layout_creates_log_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            paths = MODULE.prepare_run_layout(
                "20260419-020304",
                root / "logs",
                root / "work",
            )
            self.assertTrue(paths["log_dir"].is_dir())
            self.assertEqual(paths["work_dir"], root / "work" / "20260419-020304")

    def test_append_summary_writes_stage_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary_path = Path(tmp_dir) / "summary.txt"
            MODULE.append_summary(summary_path, "prepare_workspace", "ok", "created dirs")
            text = summary_path.read_text(encoding="utf-8")
            self.assertIn("[prepare_workspace] ok", text)
            self.assertIn("created dirs", text)

    def test_cleanup_workdir_respects_keep_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            work_dir = Path(tmp_dir) / "work"
            work_dir.mkdir()
            MODULE.cleanup_workdir(work_dir, keep_workdir=True)
            self.assertTrue(work_dir.exists())
            MODULE.cleanup_workdir(work_dir, keep_workdir=False)
            self.assertFalse(work_dir.exists())


class AxvisorGuestPlanTests(unittest.TestCase):
    def test_plan_axvisor_guest_paths_returns_expected_locations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            work_root = Path(tmp_dir)
            paths = MODULE.plan_axvisor_guest_paths(work_root)
            self.assertEqual(paths["cache_root"], work_root / "cache")
            self.assertEqual(paths["downloads_dir"], work_root / "cache" / "downloads")
            self.assertEqual(
                paths["archive_path"],
                work_root / "cache" / "downloads" / f"qemu_aarch64_linux-{MODULE.DEFAULT_AXVISOR_GUEST_REF}.tar.gz",
            )
            self.assertEqual(
                paths["extract_dir"],
                work_root / "cache" / "release" / f"qemu_aarch64_linux-{MODULE.DEFAULT_AXVISOR_GUEST_REF}",
            )

    def test_build_release_url_points_to_fixed_tag_tarball(self) -> None:
        url = MODULE.build_axvisor_guest_release_url(MODULE.DEFAULT_AXVISOR_GUEST_REF)
        self.assertEqual(
            url,
            f"https://github.com/arceos-hypervisor/axvisor-guest/releases/download/{MODULE.DEFAULT_AXVISOR_GUEST_REF}/qemu_aarch64_linux.tar.gz",
        )


class AxebpfProgramsPlanTests(unittest.TestCase):
    def test_plan_axebpf_programs_paths_returns_expected_locations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            work_root = Path(tmp_dir)
            paths = MODULE.plan_axebpf_programs_paths(work_root)
            self.assertEqual(paths["cache_root"], MODULE.DEFAULT_UPSTREAM_CACHE_ROOT)
            self.assertEqual(paths["clone_dir"], MODULE.DEFAULT_UPSTREAM_CACHE_ROOT / "axebpf-programs")
            self.assertEqual(paths["output_dir"], MODULE.DEFAULT_UPSTREAM_CACHE_ROOT / "axebpf-programs" / "output")


class EmbeddedAssetTests(unittest.TestCase):
    def test_write_embedded_assets_creates_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            staging_dir = Path(tmp_dir)
            paths = MODULE.write_embedded_assets(staging_dir)
            self.assertEqual(paths["build_config"], staging_dir / ".build.toml")
            self.assertEqual(paths["demo_c"], staging_dir / "axebpf_integration_demo.c")
            self.assertEqual(paths["demo_fallback_asm"], staging_dir / "axebpf_integration_demo_fallback.S")
            self.assertEqual(paths["guest_init"], staging_dir / "axebpf-integration-guest-init.sh")
            self.assertEqual(paths["launcher"], staging_dir / "axebpf-integration-launch.sh")
            self.assertEqual(paths["inittab"], staging_dir / "axebpf-integration.inittab")
            self.assertEqual(paths["vmconfig"], staging_dir / "linux-qemu-smp1-axebpf-integration.toml")
            for path in paths.values():
                self.assertTrue(path.exists(), path)

    def test_embedded_asset_contents_include_required_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            staging_dir = Path(tmp_dir)
            paths = MODULE.write_embedded_assets(staging_dir)
            build_config = paths["build_config"].read_text(encoding="utf-8")
            self.assertIn("hprobe", build_config)
            self.assertIn("guest-kprobe", build_config)
            self.assertIn("guest-uprobe", build_config)
            self.assertIn("fs", build_config)
            self.assertIn("demo:start", paths["demo_c"].read_text(encoding="utf-8"))
            self.assertIn("demo:done", paths["demo_c"].read_text(encoding="utf-8"))
            self.assertIn("/etc/init.d/axebpf-integration-launch.sh", paths["guest_init"].read_text(encoding="utf-8"))
            self.assertIn("/usr/bin/axebpf_integration_demo", paths["launcher"].read_text(encoding="utf-8"))
            self.assertIn("init=/init", paths["vmconfig"].read_text(encoding="utf-8"))
            self.assertNotIn("init=/bin/init", paths["vmconfig"].read_text(encoding="utf-8"))
            self.assertNotIn("init=/sbin/init", paths["vmconfig"].read_text(encoding="utf-8"))


class BuildConfigTests(unittest.TestCase):
    def test_build_axvisor_temporarily_writes_workspace_build_config(self) -> None:
        calls: list[tuple[list[str], Path | None]] = []

        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_root = Path(tmp_dir)
            source_config = temp_root / "staging.build.toml"
            source_config.write_text('features = ["guest-kprobe"]\n', encoding="utf-8")

            def fake_run(cmd, *, cwd=None, capture_output=False):  # noqa: ANN001
                self.assertFalse(capture_output)
                self.assertEqual(cmd, ["cargo", "xtask", "build"])
                self.assertEqual(cwd, temp_root)
                workspace_config = temp_root / ".build.toml"
                self.assertTrue(workspace_config.exists())
                self.assertEqual(workspace_config.read_text(encoding="utf-8"), source_config.read_text(encoding="utf-8"))
                calls.append((cmd, cwd))
                return None

            original_root = MODULE.ROOT
            original_run = MODULE.run
            try:
                MODULE.ROOT = temp_root
                MODULE.run = fake_run
                MODULE.build_axvisor(source_config)
            finally:
                MODULE.ROOT = original_root
                MODULE.run = original_run

            self.assertEqual(calls, [(["cargo", "xtask", "build"], temp_root)])
            self.assertFalse((temp_root / ".build.toml").exists())

    def test_build_axvisor_restores_existing_workspace_build_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_root = Path(tmp_dir)
            workspace_config = temp_root / ".build.toml"
            source_config = temp_root / "staging.build.toml"
            workspace_config.write_text('features = ["original"]\n', encoding="utf-8")
            source_config.write_text('features = ["guest-uprobe"]\n', encoding="utf-8")

            def fake_run(cmd, *, cwd=None, capture_output=False):  # noqa: ANN001
                self.assertEqual(workspace_config.read_text(encoding="utf-8"), source_config.read_text(encoding="utf-8"))
                return None

            original_root = MODULE.ROOT
            original_run = MODULE.run
            try:
                MODULE.ROOT = temp_root
                MODULE.run = fake_run
                MODULE.build_axvisor(source_config)
            finally:
                MODULE.ROOT = original_root
                MODULE.run = original_run

            self.assertEqual(workspace_config.read_text(encoding="utf-8"), 'features = ["original"]\n')


class BpfProgramBuildTests(unittest.TestCase):
    def test_build_axebpf_programs_uses_repo_build_script_and_returns_printk(self) -> None:
        calls: list[tuple[list[str], Path | None]] = []

        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_root = Path(tmp_dir)
            repo_dir = temp_root / "axebpf-programs"
            output_dir = repo_dir / "output"
            repo_dir.mkdir()
            output_dir.mkdir()
            (output_dir / "printk.o").write_text("fake", encoding="utf-8")

            def fake_run(cmd, *, cwd=None, capture_output=False):  # noqa: ANN001
                self.assertFalse(capture_output)
                calls.append((cmd, cwd))
                return None

            original_run = MODULE.run
            try:
                MODULE.run = fake_run
                result = MODULE.build_axebpf_programs(repo_dir, output_dir)
            finally:
                MODULE.run = original_run

            self.assertEqual(calls, [(["bash", "build.sh"], repo_dir)])
            self.assertEqual(result["printk_host"], output_dir / "printk.o")


class GuestBootFailureTests(unittest.TestCase):
    def test_guest_panic_regex_matches_kernel_panic_line(self) -> None:
        sample = "[    1.293001] Kernel panic - not syncing: Requested init /sbin/init failed (error -2)."
        self.assertIsNotNone(MODULE.GUEST_KERNEL_PANIC.search(sample))


class RootfsPlanTests(unittest.TestCase):
    def test_build_demo_compile_commands_prefers_gcc_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            staging_dir = Path(tmp_dir)
            assets = MODULE.write_embedded_assets(staging_dir)
            commands = MODULE.build_demo_compile_commands(
                assets,
                staging_dir / "axebpf_integration_demo",
                staging_dir / "axebpf-integration-demo.syms",
                prefer_gcc=True,
            )
            self.assertEqual(commands[0][0], "aarch64-linux-gnu-gcc")
            self.assertIn(str(assets["demo_c"]), commands[0])
            self.assertEqual(commands[1][0], "aarch64-linux-gnu-nm")

    def test_build_rootfs_injection_plan_contains_required_guest_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            staging_dir = Path(tmp_dir)
            assets = MODULE.write_embedded_assets(staging_dir)
            plan = MODULE.build_rootfs_injection_plan(
                Path("/tmp/rootfs.img"),
                staging_dir / "axebpf_integration_demo",
                staging_dir / "axebpf-integration-demo.syms",
                assets,
            )
            flattened = [" ".join(command) for command in plan]
            self.assertTrue(any("/usr/bin/axebpf_integration_demo" in command for command in flattened))
            self.assertTrue(any("/vmimages/axebpf-integration-demo.syms" in command for command in flattened))
            self.assertTrue(any(" /init" in command for command in flattened))
            self.assertTrue(any("/etc/init.d/axebpf-integration-launch.sh" in command for command in flattened))
            self.assertTrue(any("/etc/inittab" in command for command in flattened))
            self.assertTrue(any("/vmconfigs/linux-qemu-smp1-axebpf-integration.toml" in command for command in flattened))


class FakeChild:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.before = ""
        self.after = ""
        self._steps = [
            ("disable", "async log\n", "Verbose mode: disabled"),
            ("prompt", "", ""),
        ]

    def sendline(self, line: str) -> None:
        self.sent.append(line)

    def expect(self, patterns, timeout=None):  # noqa: ANN001
        step, before, after = self._steps.pop(0)
        self.before = before
        self.after = after
        if step == "disable":
            self._last_timeout = timeout
            assert isinstance(patterns, list), patterns
            assert patterns == [MODULE.VERBOSE_DISABLED, MODULE.EBPF_VERBOSE_DISABLED], patterns
            return 0
        assert patterns == MODULE.PROMPT, patterns
        return 0


class HarnessHelperTests(unittest.TestCase):
    def test_send_trace_verbose_off_does_not_require_prompt_before_command(self) -> None:
        child = FakeChild()
        output = MODULE.send_trace_verbose_off(child)
        self.assertEqual(output, "async log\n")
        self.assertEqual(child.sent, ["trace verbose off"])

    def test_render_terminal_text_collapses_prompt_redraw(self) -> None:
        raw = (
            "axvisor:/$ \n"
            "\x1b[2Kaxvisor:/$ t\r\x1b[2Kaxvisor:/$ tr\r\x1b[2Kaxvisor:/$ trace enable vmm:timer_tick\n"
            "Enabled: vmm:timer_tick\n"
        )
        rendered = MODULE.render_terminal_text(raw)
        self.assertIn("axvisor:/$ trace enable vmm:timer_tick", rendered)
        self.assertIn("Enabled: vmm:timer_tick", rendered)
        self.assertNotIn("\x1b[2K", rendered)


class MainOrderTests(unittest.TestCase):
    def test_main_runs_stages_in_expected_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            order: list[str] = []
            original = {
                "DEFAULT_WORK_ROOT": MODULE.DEFAULT_WORK_ROOT,
                "require_environment": MODULE.require_environment,
                "download_axvisor_guest_release": MODULE.download_axvisor_guest_release,
                "fetch_axebpf_programs": MODULE.fetch_axebpf_programs,
                "prepare_linux_base_image": MODULE.prepare_linux_base_image,
                "build_axvisor": MODULE.build_axvisor,
                "build_axebpf_programs": MODULE.build_axebpf_programs,
                "write_embedded_assets": MODULE.write_embedded_assets,
                "build_demo_binary": MODULE.build_demo_binary,
                "inject_rootfs_files": MODULE.inject_rootfs_files,
                "verify_injected_rootfs": MODULE.verify_injected_rootfs,
                "run_qemu_integration": MODULE.run_qemu_integration,
                "run_checker": MODULE.run_checker,
                "cleanup_workdir": MODULE.cleanup_workdir,
            }
            try:
                MODULE.DEFAULT_WORK_ROOT = root / "work-root"

                def fake_require_environment() -> None:
                    order.append("check_environment")

                def fake_download_axvisor_guest_release(paths, ref, *, reuse_clone):  # noqa: ANN001
                    order.append("download_axvisor_guest_release")
                    return paths

                def fake_fetch_axebpf_programs(paths, *, reuse_clone):  # noqa: ANN001
                    order.append("fetch_axebpf_programs")
                    return paths

                def fake_prepare_linux_base_image(run_paths, release_paths):  # noqa: ANN001
                    order.append("prepare_linux_base_image")
                    run_paths["linux_guest_bin"] = root / "linux.bin"
                    run_paths["linux_guest_syms"] = root / "linux.syms"
                    run_paths["run_rootfs_image"] = root / "rootfs.img"
                    return {}

                def fake_build_axvisor(build_config_path) -> None:  # noqa: ANN001
                    order.append("build_axvisor")
                    self.assertEqual(build_config_path.name, ".build.toml")
                    self.assertEqual(build_config_path.parent.name, "staging")
                    self.assertEqual(build_config_path.parent.parent.parent, root / "work-root")

                def fake_build_axebpf_programs(repo_dir, output_dir):  # noqa: ANN001
                    order.append("build_axebpf_programs")
                    return {"printk_host": output_dir / "printk.o"}

                def fake_write_embedded_assets(staging_dir):  # noqa: ANN001
                    order.append("write_embedded_assets")
                    return {
                        "build_config": staging_dir / ".build.toml",
                        "demo_c": staging_dir / "demo.c",
                        "demo_fallback_asm": staging_dir / "demo.S",
                        "launcher": staging_dir / "launch.sh",
                        "inittab": staging_dir / "inittab",
                        "vmconfig": staging_dir / "vmconfig.toml",
                    }

                def fake_build_demo_binary(assets, build_dir):  # noqa: ANN001
                    order.append("build_demo_binary")
                    return {
                        "demo_bin": build_dir / "demo.bin",
                        "demo_syms": build_dir / "demo.syms",
                    }

                def fake_inject_rootfs_files(rootfs_image, linux_guest_bin, linux_guest_syms, printk_host, assets, demo_outputs):  # noqa: ANN001
                    order.append("inject_rootfs_files")

                def fake_verify_injected_rootfs(rootfs_image):  # noqa: ANN001
                    order.append("verify_injected_rootfs")

                def fake_run_qemu_integration(run_paths):  # noqa: ANN001
                    order.append("run_qemu_integration")

                class FakeResult:
                    stdout = ""
                    stderr = ""
                    returncode = 0

                def fake_run_checker(log_path):  # noqa: ANN001
                    order.append("check_log")
                    return FakeResult()

                def fake_cleanup_workdir(work_dir, *, keep_workdir):  # noqa: ANN001
                    order.append("cleanup_workdir")

                MODULE.require_environment = fake_require_environment
                MODULE.download_axvisor_guest_release = fake_download_axvisor_guest_release
                MODULE.fetch_axebpf_programs = fake_fetch_axebpf_programs
                MODULE.prepare_linux_base_image = fake_prepare_linux_base_image
                MODULE.build_axvisor = fake_build_axvisor
                MODULE.build_axebpf_programs = fake_build_axebpf_programs
                MODULE.write_embedded_assets = fake_write_embedded_assets
                MODULE.build_demo_binary = fake_build_demo_binary
                MODULE.inject_rootfs_files = fake_inject_rootfs_files
                MODULE.verify_injected_rootfs = fake_verify_injected_rootfs
                MODULE.run_qemu_integration = fake_run_qemu_integration
                MODULE.run_checker = fake_run_checker
                MODULE.cleanup_workdir = fake_cleanup_workdir

                exit_code = MODULE.main(["--logs-dir", str(root / "logs")])

                self.assertEqual(exit_code, 0)
                self.assertEqual(
                    order,
                    [
                        "check_environment",
                        "download_axvisor_guest_release",
                        "fetch_axebpf_programs",
                        "prepare_linux_base_image",
                        "write_embedded_assets",
                        "build_axvisor",
                        "build_axebpf_programs",
                        "build_demo_binary",
                        "inject_rootfs_files",
                        "verify_injected_rootfs",
                        "run_qemu_integration",
                        "cleanup_workdir",
                        "check_log",
                    ],
                )
            finally:
                for name, value in original.items():
                    setattr(MODULE, name, value)


if __name__ == "__main__":
    unittest.main()
