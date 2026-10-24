"""NT device paths become DOS paths through the drive-letter map."""

from windows_medic.infrastructure.windows.process_access import dos_path

DEVICES = {"\\Device\\HarddiskVolume3": "C:", "\\Device\\HarddiskVolume12": "D:"}


def test_a_mapped_device_becomes_its_drive_letter() -> None:
    assert (
        dos_path("\\Device\\HarddiskVolume3\\Windows\\System32\\csrss.exe", DEVICES)
        == "C:\\Windows\\System32\\csrss.exe"
    )


def test_device_names_match_case_insensitively_and_whole() -> None:
    assert dos_path("\\device\\harddiskvolume12\\x.exe", DEVICES) == "D:\\x.exe"
    # Volume1 must not swallow Volume12's prefix, and vice versa.
    assert dos_path("\\Device\\HarddiskVolume1\\x.exe", DEVICES) == (
        "\\Device\\HarddiskVolume1\\x.exe"
    )


def test_paths_without_a_device_are_returned_unchanged() -> None:
    assert dos_path("Registry", DEVICES) == "Registry"
    assert dos_path("", DEVICES) == ""
