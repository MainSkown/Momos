import src.schemas.test_session_scheme as session_scheme


def test_last_resumed_at_is_not_exposed_in_response():
    assert "last_resumed_at" not in session_scheme.TestSessionResponse.model_fields


def test_detail_response_adds_only_derived_counts_to_response_fields():
    detail_fields = set(session_scheme.TestSessionDetailResponse.model_fields)
    response_fields = set(session_scheme.TestSessionResponse.model_fields)

    assert detail_fields - response_fields == {"vector_counts", "vulnerability_count"}
