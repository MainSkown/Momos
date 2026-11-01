from src.schemas.ollama_connection_scheme import ollama_connection_settings_factory


def test_factory_defaults_mode_to_local():
    assert ollama_connection_settings_factory().mode == "local"


def test_factory_defaults_remote_url_to_empty():
    assert ollama_connection_settings_factory().remote_url == ""


def test_factory_defaults_remote_api_key_to_none():
    assert ollama_connection_settings_factory().remote_api_key_encrypted is None
