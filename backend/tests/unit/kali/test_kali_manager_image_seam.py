"""The §1.4a live-tool tier needs to point KaliManger at a lightweight
test image instead of the real Kali one - this is the seam that makes
that possible, added as its own reviewed change per docs/testing-plan.md
§1.4a. Verifies the seam itself: default unchanged, override honored."""

from unittest.mock import MagicMock, patch

import docker.errors

from src.core.kali_integration.kali_manager import KaliManger


def test_default_image_is_the_real_kali_image():
    with patch("src.core.kali_integration.kali_manager.docker.from_env"):
        manager = KaliManger()

    assert manager.image == "kalilinux/kali-rolling:latest"


def test_image_override_is_honored():
    with patch("src.core.kali_integration.kali_manager.docker.from_env"):
        manager = KaliManger(image="alpine:latest")

    assert manager.image == "alpine:latest"


def test_create_container_runs_with_the_manager_own_image():
    with patch("src.core.kali_integration.kali_manager.docker.from_env") as from_env:
        fake_client = MagicMock()
        from_env.return_value = fake_client
        fake_client.containers.get.side_effect = docker.errors.NotFound(
            "no existing container"
        )
        # _create_container goes on to _configure_container's real exec_run
        # calls - not this test's concern, just needs to look like success
        # so the image-kwarg assertion below is actually reached.
        fake_client.containers.run.return_value.exec_run.return_value = (
            MagicMock(exit_code=0, output=b"")
        )

        manager = KaliManger(image="alpine:latest")
        manager._create_container(on_stage=None)

    _, kwargs = fake_client.containers.run.call_args
    assert kwargs["image"] == "alpine:latest"
