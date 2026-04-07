from main import DebugPlatformClient, run_self_check


def test_run_self_check_returns_status_code():
    code = run_self_check({"llm": {"active_model": "deepseek-chat"}})
    assert code in (0, 1)


def test_debug_platform_rejects_placeholder_flags():
    client = DebugPlatformClient()
    result = client.submit_flag("debug-chal-1", "flag{...}")
    assert result.success is False
    assert "rejected" in result.message
