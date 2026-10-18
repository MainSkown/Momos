from src.schemas.kali_scheme import KaliCreationStage


def test_creation_stage_formats_as_bare_value():
    stage = KaliCreationStage.installing_packages

    assert str(stage) == "installing_packages"
    assert f"{stage}" == "installing_packages"
