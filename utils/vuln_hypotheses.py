"""First-principles vulnerability hypothesis engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List


@dataclass
class VulnerabilityHypothesis:
    key: str
    family: str
    title: str
    confidence: float
    evidence: List[str]
    prerequisites: List[str]
    next_step: str


def _contains_all(text: str, needles: Iterable[str]) -> bool:
    return all(needle in text for needle in needles)


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    return any(needle in text for needle in needles)


def infer_vulnerability_hypotheses(
    observations: List[str],
    services: Dict[str, Dict[int, str]] | None = None,
    findings: List[str] | None = None,
) -> List[VulnerabilityHypothesis]:
    corpus = "\n".join(observations + list(findings or [])).lower()
    service_text = "\n".join(
        service
        for host_services in (services or {}).values()
        for service in host_services.values()
    ).lower()
    combined = corpus + "\n" + service_text

    hypotheses: List[VulnerabilityHypothesis] = []

    if _contains_any(combined, ["apache shiro", "shiro quickstart", "rememberme"]) and _contains_any(
        combined, ["rememberme=deleteme", "remember me", "login.jsp"]
    ):
        evidence = []
        if "rememberme=deleteme" in combined:
            evidence.append("Response sets rememberMe=deleteMe")
        if "apache shiro" in combined or "shiro quickstart" in combined:
            evidence.append("Application fingerprint indicates Apache Shiro")
        if "login.jsp" in combined and "remember me" in combined:
            evidence.append("Login flow exposes rememberMe checkbox")
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:shiro-cve_2016_4437",
                family="known_cve",
                title="Apache Shiro rememberMe default-key deserialization (CVE-2016-4437)",
                confidence=0.95 if "rememberme=deleteme" in combined else 0.82,
                evidence=evidence,
                prerequisites=[
                    "rememberMe cookie handling is present",
                    "target uses a vulnerable Shiro version or default/known key configuration",
                    "standard Shiro helper tooling or validated payload generation is available",
                ],
                next_step=(
                    "Use the known-CVE / Java-deserialization methodology and validate the Shiro key path "
                    "before trying alternate vulnerability families."
                ),
            )
        )

    if _contains_any(combined, ["application/x-java-serialized-object", "aced0005", "ysoserial", "deserialization"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:java-deserialization",
                family="deserialization",
                title="Java deserialization attack surface",
                confidence=0.72,
                evidence=["Serialized-object handling or ysoserial-related evidence observed"],
                prerequisites=[
                    "Attacker-controlled serialized data reaches a deserializer",
                    "A suitable gadget chain exists on the server classpath",
                ],
                next_step="Validate entrypoint, gadget availability, and echo/no-echo constraints before exploit attempts.",
            )
        )

    if _contains_any(combined, ["jinja2", "render_template_string", "template syntax error", "{{7*7}}", "freemarker", "thymeleaf", "velocity"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:ssti",
                family="template_injection",
                title="Server-side template injection candidate",
                confidence=0.81,
                evidence=["Template-engine markers or template-evaluation behavior observed"],
                prerequisites=[
                    "Attacker-controlled input is rendered by a template engine",
                    "The template engine allows expression evaluation or object traversal",
                ],
                next_step="Confirm expression evaluation with low-noise arithmetic probes, then map sandbox boundaries and reachable objects.",
            )
        )

    if _contains_any(combined, ["multipart/form-data", "filename=", "content-disposition: form-data", "move_uploaded_file", "upload success", "/uploads/"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:file-upload",
                family="file_write",
                title="File upload attack surface",
                confidence=0.77,
                evidence=["Multipart upload workflow or upload storage path observed"],
                prerequisites=[
                    "User-controlled file content reaches storage",
                    "Validation, naming, and serving paths are weak enough to allow abuse",
                ],
                next_step="Verify extension/MIME checks, storage path predictability, and whether uploaded files are web-reachable or parser-reachable.",
            )
        )

    if _contains_any(combined, ["<!doctype foo", "<!entity", "xml parser", "application/xml", "text/xml", "xxe", "libxml"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:xxe",
                family="xml_processing",
                title="XML external entity injection candidate",
                confidence=0.76,
                evidence=["XML parsing surface or entity-related parser behavior observed"],
                prerequisites=[
                    "Attacker-controlled XML is parsed",
                    "External entity resolution or dangerous parser features are enabled",
                ],
                next_step="Confirm parser type, DTD handling, and whether the sink allows file disclosure, SSRF, or OOB resolution.",
            )
        )

    if _contains_any(combined, ["169.254.169.254", "metadata.google.internal", "latest/meta-data", "x-aws-ec2-metadata-token", "gopher://", "dict://", "file://"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:ssrf-cloud-metadata",
                family="ssrf",
                title="SSRF candidate with cloud/internal pivot potential",
                confidence=0.84,
                evidence=["Metadata-service or internal URL fetch indicators observed"],
                prerequisites=[
                    "Attacker controls a server-side URL fetch sink",
                    "Network policy permits access to internal services or cloud metadata",
                ],
                next_step="Determine allowed schemes/hosts, redirect behavior, and whether metadata or internal admin services are reachable.",
            )
        )

    if _contains_any(combined, ["sample accounts", "default text-based realm", "root/secret", "admin/admin"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:weak-default-auth",
                family="authentication",
                title="Weak or default credentials",
                confidence=0.78,
                evidence=["Login workflow exposes sample or default credentials"],
                prerequisites=["Authentication backend accepts documented sample credentials"],
                next_step="Complete authenticated path mapping first and check for privilege-separated content and post-auth attack surface.",
            )
        )

    if _contains_any(combined, ["access-control-allow-origin", "access-control-allow-credentials", "cors"]) and _contains_any(
        combined, ["origin:", "null", "*", "credentials"]
    ):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:cors-misconfig",
                family="browser_security",
                title="CORS misconfiguration candidate",
                confidence=0.73,
                evidence=["CORS response headers suggest broad or credentialed cross-origin trust"],
                prerequisites=[
                    "Sensitive content is readable cross-origin",
                    "Origin validation is weak, reflective, or over-broad",
                ],
                next_step="Check whether attacker-controlled origins can read authenticated responses or sensitive unauthenticated data.",
            )
        )

    if _contains_any(combined, ["oauth", "redirect_uri", "authorization code", "state=", "openid connect", "sso"]) or _contains_any(
        combined, ["client_id=", "response_type=code", "/oauth/authorize"]
    ):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:oauth-sso",
                family="authentication",
                title="OAuth / SSO flow abuse candidate",
                confidence=0.75,
                evidence=["OAuth or SSO protocol markers observed"],
                prerequisites=[
                    "Authorization flow parameters are attacker-influenced",
                    "Redirect, state, account-binding, or token validation logic is weak",
                ],
                next_step="Map the full authorization flow and validate redirect_uri, state binding, issuer trust, and account-linking behavior.",
            )
        )

    if _contains_any(combined, ["sql syntax", "error in your sql", "postgresql", "sqlite", "oracle", "mysql"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:sql-injection",
                family="injection",
                title="SQL injection candidate",
                confidence=0.74,
                evidence=["Database-flavored error strings or SQL parser behavior observed"],
                prerequisites=["An input parameter is reflected into a database query"],
                next_step="Confirm parameter controllability, error-based behavior, and stable response differentials.",
            )
        )

    if _contains_any(combined, ["graphql", "__schema", "__type", "introspection", "graphiql", "graphql playground"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:graphql-exposure",
                family="api",
                title="GraphQL exposure / introspection candidate",
                confidence=0.71,
                evidence=["GraphQL endpoint or introspection artifacts observed"],
                prerequisites=[
                    "GraphQL schema or object resolvers expose sensitive fields or weak authorization boundaries",
                ],
                next_step="Check introspection, hidden mutations, object-level authorization, batching, and resolver-specific trust boundaries.",
            )
        )

    if _contains_any(combined, ["user_id", "author_id", "objectid", "idor", "insecure direct object reference", "forbidden for one id but 200 for another"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:idor",
                family="access_control",
                title="IDOR / object-level authorization candidate",
                confidence=0.79,
                evidence=["Object identifiers or access-control differential behavior observed"],
                prerequisites=[
                    "A predictable or discoverable object identifier is attacker-controlled",
                    "Authorization is missing or inconsistent at the object layer",
                ],
                next_step="Identify stable object identifiers and compare read/write behavior across identities or object owners.",
            )
        )

    if _contains_any(combined, ["root:", "php://filter", "../../../../", "../..", "/etc/passwd"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:file-inclusion",
                family="file_access",
                title="Local file inclusion / path traversal candidate",
                confidence=0.7,
                evidence=["Filesystem markers or traversal payload artifacts observed"],
                prerequisites=["A file/path parameter is attacker-controlled and insufficiently normalized"],
                next_step="Verify readable path boundaries and whether source disclosure or sensitive file reads are possible.",
            )
        )

    if _contains_any(combined, ["jwt", "alg:none", "kid", "jwks", "jsonwebtoken", "bearer "]) or _contains_any(
        combined, ["authorization: bearer", "jwt secret"]
    ):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:jwt",
                family="token_security",
                title="JWT trust-boundary weakness candidate",
                confidence=0.77,
                evidence=["JWT-specific parsing, signing, or trust markers observed"],
                prerequisites=[
                    "Application trusts attacker-influenced token headers, claims, or key selection",
                ],
                next_step="Confirm algorithm handling, key selection, claim validation, and whether tokens are bound to the correct issuer/audience/context.",
            )
        )

    if _contains_any(combined, ["struts2", ".action", ".do", "ognl", "multipart parser"]) or _contains_any(
        combined, ["s2-045", "s2-057", "s2-061"]
    ):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:struts2-rce",
                family="known_cve",
                title="Struts2 OGNL injection / known-CVE candidate",
                confidence=0.82,
                evidence=["Struts2 endpoint patterns or OGNL-related indicators observed"],
                prerequisites=[
                    "Target uses a vulnerable Struts2 component path",
                    "Attacker-controlled input reaches OGNL evaluation or vulnerable parser code",
                ],
                next_step="Confirm framework/version clues and test low-noise OGNL evaluation indicators before broader exploit attempts.",
            )
        )

    if _contains_any(combined, ["fastjson", "@type", "com.alibaba.fastjson", "autoType", "json parser exception"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:fastjson",
                family="known_cve",
                title="Fastjson unsafe autoType / deserialization candidate",
                confidence=0.8,
                evidence=["Fastjson-specific parser artifacts observed"],
                prerequisites=[
                    "Attacker-controlled JSON reaches Fastjson parsing",
                    "autoType or a vulnerable code path is still reachable",
                ],
                next_step="Validate Fastjson version traits, parser errors, and whether attacker-controlled @type processing is possible.",
            )
        )

    if _contains_any(combined, ["${jndi:", "log4j", "x-api-version", "x-forwarded-for", "jndi lookup"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:log4shell",
                family="known_cve",
                title="Log4Shell / JNDI injection candidate",
                confidence=0.83,
                evidence=["JNDI lookup syntax or Log4j markers observed"],
                prerequisites=[
                    "Attacker-controlled input is logged by vulnerable Log4j code",
                    "JNDI lookups or related exploitation path remains reachable",
                ],
                next_step="Verify which request components are logged and whether lookup evaluation is triggered in a controlled manner.",
            )
        )

    if _contains_any(combined, ["spring4shell", "class.module.classloader", "spring mvc", "war deployment", "tomcat valve"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:spring4shell",
                family="known_cve",
                title="Spring4Shell candidate",
                confidence=0.78,
                evidence=["Spring4Shell-specific field or deployment markers observed"],
                prerequisites=[
                    "Vulnerable Spring MVC deployment conditions are met",
                    "Attacker-controlled request parameters reach the vulnerable binder path",
                ],
                next_step="Validate deployment preconditions (WAR/JDK/Tomcat path) before assuming exploitability.",
            )
        )

    if _contains_any(combined, ["uid=", "gid=", "whoami", "command injection detected"]):
        hypotheses.append(
            VulnerabilityHypothesis(
                key="hypothesis:command-injection",
                family="command_execution",
                title="Command injection candidate",
                confidence=0.8,
                evidence=["Command-execution output markers observed"],
                prerequisites=["Attacker input reaches a shell or command execution sink"],
                next_step="Stabilize execution primitive and pivot toward low-noise verification or flag discovery.",
            )
        )

    hypotheses.sort(key=lambda item: (-item.confidence, item.key))
    return hypotheses


def summarize_hypotheses(hypotheses: List[VulnerabilityHypothesis], limit: int = 3) -> str:
    if not hypotheses:
        return ""
    lines = ["Top vulnerability hypotheses:"]
    for hypothesis in hypotheses[:limit]:
        evidence = "; ".join(hypothesis.evidence[:2]) if hypothesis.evidence else "no evidence recorded"
        lines.append(
            f"- {hypothesis.title} [{hypothesis.family}] confidence={hypothesis.confidence:.2f} | {evidence}"
        )
        lines.append(f"  Next: {hypothesis.next_step}")
    return "\n".join(lines)
