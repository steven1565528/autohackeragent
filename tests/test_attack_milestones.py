from utils.attack_milestones import infer_attack_milestones


def test_infer_shiro_milestones_from_progress_signals():
    milestones = infer_attack_milestones(
        [
            "Apache Shiro Quickstart",
            "Set-Cookie: rememberMe=deleteMe",
            "You are currently logged in.",
            "Generated rememberMe cookie length: 1920",
        ]
    )
    keys = {milestone.key for milestone in milestones}
    assert "milestone:shiro:fingerprint" in keys
    assert "milestone:shiro:key-validation" in keys
    assert "milestone:shiro:auth" in keys
    assert "milestone:shiro:payload-execution-attempt" in keys


def test_infer_sql_and_upload_milestones():
    milestones = infer_attack_milestones(
        [
            "SQL syntax error near MySQL",
            "UNION SELECT 1,2,3",
            "Content-Type: multipart/form-data; boundary=abc",
            'filename="shell.jsp"',
        ]
    )
    keys = {milestone.key for milestone in milestones}
    assert "milestone:sql:error-signal" in keys
    assert "milestone:sql:exploitation-attempt" in keys
    assert "milestone:file-upload:write-surface" in keys
