from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_firmware_ack_state_cpp_harness(tmp_path):
    compiler = shutil.which("g++") or shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        pytest.skip("A native C++ compiler is not installed.")

    repository = Path(__file__).resolve().parents[1]
    executable = tmp_path / "firmware_ack_state_test"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(repository / "wowki"),
            str(repository / "tests" / "firmware_ack_state_test.cpp"),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
