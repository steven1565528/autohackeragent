"""Attack-stage milestone inference from observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class AttackMilestone:
    key: str
    family: str
    stage: str
    evidence: List[str]


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    return any(needle in text for needle in needles)


def infer_attack_milestones(observations: List[str]) -> List[AttackMilestone]:
    combined = "\n".join(observations).lower()
    milestones: List[AttackMilestone] = []

    if _contains_any(combined, ["apache shiro", "shiro quickstart", "remember me", "rememberme"]):
        milestones.append(
            AttackMilestone(
                key="milestone:shiro:fingerprint",
                family="exploit:shiro_deserialization",
                stage="fingerprint",
                evidence=["Shiro-specific application markers observed"],
            )
        )
    if _contains_any(combined, ["root/secret", "sample accounts", "currently logged in", "/account/"]):
        milestones.append(
            AttackMilestone(
                key="milestone:shiro:auth",
                family="exploit:shiro_deserialization",
                stage="auth",
                evidence=["Authenticated Shiro path or sample credentials observed"],
            )
        )
    if "rememberme=deleteme" in combined:
        milestones.append(
            AttackMilestone(
                key="milestone:shiro:key-validation",
                family="exploit:shiro_deserialization",
                stage="validation",
                evidence=["rememberMe deleteMe behavior confirms Shiro rememberMe processing"],
            )
        )
    if _contains_any(combined, ["generated rememberme cookie", "payload length:", "no deleteme!", "gadget", "ysoserial"]):
        milestones.append(
            AttackMilestone(
                key="milestone:shiro:payload-execution-attempt",
                family="exploit:shiro_deserialization",
                stage="exploit",
                evidence=["Serialized payload generation or execution attempt observed"],
            )
        )

    if _contains_any(combined, ["sql syntax", "error in your sql", "mysql", "postgresql", "sqlite", "oracle"]):
        milestones.append(
            AttackMilestone(
                key="milestone:sql:error-signal",
                family="exploit:sql_injection",
                stage="validation",
                evidence=["Database error signal observed"],
            )
        )
    if _contains_any(combined, ["union select", "extractvalue", "group_concat", "order by"]):
        milestones.append(
            AttackMilestone(
                key="milestone:sql:exploitation-attempt",
                family="exploit:sql_injection",
                stage="exploit",
                evidence=["SQL injection exploitation primitives observed"],
            )
        )

    if _contains_any(combined, ["multipart/form-data", "filename=", "/uploads/", "upload success"]):
        milestones.append(
            AttackMilestone(
                key="milestone:file-upload:write-surface",
                family="exploit:file_upload",
                stage="validation",
                evidence=["File upload sink or storage path observed"],
            )
        )

    if _contains_any(combined, ["<!doctype", "<!entity", "application/xml", "text/xml"]):
        milestones.append(
            AttackMilestone(
                key="milestone:xxe:xml-sink",
                family="exploit:xxe",
                stage="validation",
                evidence=["XML parsing sink observed"],
            )
        )

    if _contains_any(combined, ["169.254.169.254", "latest/meta-data", "metadata.google.internal"]):
        milestones.append(
            AttackMilestone(
                key="milestone:ssrf:metadata-reachability",
                family="exploit:ssrf",
                stage="validation",
                evidence=["Cloud metadata path or internal fetch target observed"],
            )
        )

    if _contains_any(combined, ["graphql", "__schema", "__type", "graphiql", "graphql playground"]):
        milestones.append(
            AttackMilestone(
                key="milestone:graphql:schema-exposure",
                family="exploit:graphql",
                stage="validation",
                evidence=["GraphQL schema or introspection surface observed"],
            )
        )

    if _contains_any(combined, ["user_id", "author_id", "idor", "insecure direct object reference"]):
        milestones.append(
            AttackMilestone(
                key="milestone:idor:object-identifier",
                family="exploit:idor",
                stage="validation",
                evidence=["Controllable object identifiers observed"],
            )
        )

    if _contains_any(combined, ["authorization: bearer", "jwt", "alg:none", "jwks", "kid"]):
        milestones.append(
            AttackMilestone(
                key="milestone:jwt:token-surface",
                family="exploit:jwt_attack",
                stage="validation",
                evidence=["JWT trust surface observed"],
            )
        )

    return milestones
