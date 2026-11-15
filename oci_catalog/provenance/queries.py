"""证明评价与两类治理查询（在新进程中打开证据库 + 策略即可运行）。

评价语义：

* 每次评价都从库中取出**原始证据**（payload 原字节、签名原字节），用
  调用者当前给出的策略即时验签与计票；不沿用任何旧策略的通过标志；
* 验签数据是 PAE（见 :mod:`dsse`），对 payload 原始字节验签；
* 签名者身份由**实际验签**决定：逐个尝试策略登记的公钥，keyid 只作
  提示；同一公钥的多个别名、同一公钥的重复签名都只算一票；
* 票数只在**同一信封的同一原始载荷**内累计——不同证据行之间绝不合票；
* 无效签名与未知签名者各自留下诊断，但不阻断：达到规则门槛的独立授权
  公钥数足够时，同一份证据仍判可信；
* 每次评价（无论结论）都追加到 ``evaluations``，记录策略内容摘要与
  结论，便于说明某次结论依据哪套规则。

重要限制：评价结论只说明“获授权的密钥签过这份绑定声明”，**不**证明
镜像确实按声明执行过构建。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..digest import DigestError, parse_digest
from .dsse import ed25519_verify, pae
from .policy import Policy, key_fingerprint
from .store import ProvenanceStore

# 评价结论
TRUSTED = "trusted"
UNTRUSTED = "untrusted"

# 结论原因
REASON_THRESHOLD_MET = "threshold_met"
REASON_NO_MATCHING_RULE = "no_matching_rule"
REASON_NO_VALID_SIGNATURES = "no_valid_signatures"
REASON_THRESHOLD_NOT_MET = "threshold_not_met"

# 单条签名的验签状态
SIG_VERIFIED = "verified"
SIG_INVALID = "invalid_signature"
SIG_UNKNOWN_SIGNER = "unknown_signer"


@dataclass
class SignatureReport:
    """一条签名在当前策略下的验签结果。"""

    index: int
    keyid: str | None
    status: str                     # verified / invalid_signature / unknown_signer
    fingerprint: str | None = None  # verified 时为实际验证出的公钥指纹
    counted: bool = False           # 是否计入规则门槛
    note: str | None = None         # 诊断说明（keyid 不符、无法验签等）

    def to_dict(self) -> dict:
        return {
            "index": self.index, "keyid": self.keyid, "status": self.status,
            "fingerprint": self.fingerprint, "counted": self.counted,
            "note": self.note,
        }


@dataclass
class Evaluation:
    """一份证据在当前策略下的完整评价。"""

    evidence_id: int
    verdict: str
    reason: str
    policy_sha256: str
    rule_id: str | None = None
    threshold: int | None = None
    counted_fingerprints: list[str] = field(default_factory=list)
    signatures: list[SignatureReport] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "policy_sha256": self.policy_sha256,
            "rule_id": self.rule_id,
            "threshold": self.threshold,
            "counted_fingerprints": self.counted_fingerprints,
            "signatures": [s.to_dict() for s in self.signatures],
        }


def evaluate_evidence(store: ProvenanceStore, evidence,
                      policy: Policy, record: bool = True) -> Evaluation:
    """对一行证据按当前策略即时评价；默认把结论追加到评价历史。

    :param evidence: ``evidence`` 表行（含 payload_type/payload_bytes/
        builder_id/build_type）。
    """
    evidence_id = evidence["evidence_id"]
    message = pae(evidence["payload_type"], evidence["payload_bytes"])
    distinct_keys = policy.distinct_fingerprints  # 指纹 -> 公钥字节

    reports: list[SignatureReport] = []
    verified_fps: list[str] = []  # 实际验证出的独立指纹（按签名出现顺序去重）
    for row in store.list_signatures(evidence_id):
        keyid = row["keyid"]
        sig = bytes.fromhex(row["sig_hex"])
        fingerprint = None
        for fp, public_bytes in distinct_keys.items():
            if ed25519_verify(public_bytes, message, sig):
                fingerprint = fp
                break
        if fingerprint is not None:
            note = None
            if keyid is not None:
                hinted = set(policy.names_for_fingerprint(fingerprint))
                hinted.add(fingerprint)
                if keyid not in hinted:
                    note = (f"keyid {keyid!r} 与实际验证出的公钥指纹 "
                            f"{fingerprint} 不符；keyid 仅作提示，"
                            f"身份以验签结果为准")
            report = SignatureReport(
                index=row["sig_index"], keyid=keyid, status=SIG_VERIFIED,
                fingerprint=fingerprint, note=note)
            if fingerprint not in verified_fps:
                verified_fps.append(fingerprint)
        else:
            # 无法验签：keyid 指向已登记公钥 -> 签名不成立；否则未知签名者
            known_names = set(policy.keys) | set(distinct_keys)
            if keyid is not None and keyid in known_names:
                status, note = SIG_INVALID, (
                    f"keyid 指向已登记公钥 {keyid!r}，但签名无法用任何"
                    f"已登记公钥验出（签名不成立）")
            else:
                status, note = SIG_UNKNOWN_SIGNER, (
                    "签名无法用策略中任何已登记公钥验出（未知签名者）")
            report = SignatureReport(
                index=row["sig_index"], keyid=keyid, status=status,
                note=note)
        reports.append(report)

    rule = policy.find_rule(evidence["builder_id"], evidence["build_type"])
    if rule is None:
        evaluation = Evaluation(
            evidence_id=evidence_id, verdict=UNTRUSTED,
            reason=REASON_NO_MATCHING_RULE,
            policy_sha256=policy.policy_sha256,
            signatures=reports)
    else:
        authorized = set(rule.authorized_fingerprints)
        counted = [fp for fp in verified_fps if fp in authorized]
        for report in reports:
            if report.status == SIG_VERIFIED and \
                    report.fingerprint in authorized:
                report.counted = True
        if len(counted) >= rule.threshold:
            verdict, reason = TRUSTED, REASON_THRESHOLD_MET
        elif not verified_fps:
            verdict, reason = UNTRUSTED, REASON_NO_VALID_SIGNATURES
        else:
            verdict, reason = UNTRUSTED, REASON_THRESHOLD_NOT_MET
        evaluation = Evaluation(
            evidence_id=evidence_id, verdict=verdict, reason=reason,
            policy_sha256=policy.policy_sha256, rule_id=rule.rule_id,
            threshold=rule.threshold, counted_fingerprints=counted,
            signatures=reports)

    if record:
        store.record_evaluation(
            evidence_id, policy.policy_sha256, evaluation.verdict,
            evaluation.reason, evaluation.counted_fingerprints,
            [s.to_dict() for s in reports])
    return evaluation


# ---------------------------------------------------------------------------
# 查询 1：镜像 -> 每份构建证明
# ---------------------------------------------------------------------------
def query_image_provenance(store: ProvenanceStore, image_digest: str,
                           policy: Policy) -> dict:
    """按镜像列出它的每份构建证明及在当前策略下的评价。

    同一镜像存在相互不同的合法声明时逐份展示，不擅自认定某一份是真实
    历史；每份都给出绑定命中的 subject 位置、构建者、构建类型、任务
    标识、材料原位置、实际验证出的公钥指纹、计入门槛的签名与整体原因。
    """
    try:
        algorithm, _ = parse_digest(image_digest)
        if algorithm != "sha256":
            raise DigestError("只支持 sha256")
    except DigestError as exc:
        raise ValueError(f"查询目标不是合法 sha256 digest: {exc}") from exc

    rows = store.list_evidence_for_image(image_digest)
    if not rows:
        raise KeyError(f"该镜像没有任何已导入的构建证明: {image_digest}")

    reports = []
    for evidence in rows:
        evaluation = evaluate_evidence(store, evidence, policy)
        subjects = [dict(row) for row in store.list_subjects(
            evidence["evidence_id"])]
        materials = [dict(row) for row in store.list_materials(
            evidence["evidence_id"])]
        reports.append({
            "evidence_id": evidence["evidence_id"],
            "envelope_sha256": evidence["envelope_sha256"],
            "payload_sha256": evidence["payload_sha256"],
            "source_path": evidence["source_path"],
            "imported_at": evidence["imported_at"],
            "builder_id": evidence["builder_id"],
            "build_type": evidence["build_type"],
            "invocation_id": evidence["invocation_id"],
            "bound_subject_indices": [
                s["subject_index"] for s in subjects if s["matched"]],
            "subjects": subjects,
            "materials": materials,
            "evaluation": evaluation.to_dict(),
        })
    return {
        "image_digest": image_digest,
        "platform": store.lookup_image_platform(image_digest),
        "policy_sha256": policy.policy_sha256,
        "evidence": reports,
        "note": ("每份证明独立评价；'trusted' 只表示获授权密钥签过这份"
                 "绑定声明，不证明镜像确实按声明执行过构建"),
    }


# ---------------------------------------------------------------------------
# 查询 2：材料坐标 -> 具有可信证明的镜像
# ---------------------------------------------------------------------------
def query_material_images(store: ProvenanceStore, uri: str, sha256: str,
                          policy: Policy) -> dict:
    """按材料 URI 与 sha256 精确反查在**当前策略下具有可信证明**的镜像。

    未通过当前策略评价的证据（未达门槛、无匹配规则、签名不成立）一律
    不进入结果；同一材料在一份证明中出现多次时，全部原位置都带回。
    """
    if not uri:
        raise ValueError("查询材料 uri 不能为空")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256 or ""):
        raise ValueError(f"查询材料 sha256 必须是 64 位十六进制: {sha256!r}")
    wanted = sha256.lower()

    rows = store.conn.execute(
        "SELECT m.evidence_id, m.material_index, e.image_digest "
        "FROM evidence_materials m "
        "JOIN evidence e ON e.evidence_id = m.evidence_id "
        "WHERE m.uri = ? AND m.sha256 = ? "
        "ORDER BY m.evidence_id, m.material_index",
        (uri, wanted)).fetchall()

    # 按证据分组：一份证据在当前策略下只评价一次
    positions: dict[int, list[int]] = {}
    for row in rows:
        positions.setdefault(row["evidence_id"], []).append(
            row["material_index"])

    matches = []
    for evidence_id in sorted(positions):
        evidence = store.get_evidence(evidence_id)
        evaluation = evaluate_evidence(store, evidence, policy)
        if evaluation.verdict != TRUSTED:
            continue
        matches.append({
            "image_digest": evidence["image_digest"],
            "evidence_id": evidence_id,
            "envelope_sha256": evidence["envelope_sha256"],
            "builder_id": evidence["builder_id"],
            "build_type": evidence["build_type"],
            "invocation_id": evidence["invocation_id"],
            "material_positions": positions[evidence_id],
        })
    return {
        "uri": uri,
        "sha256": wanted,
        "policy_sha256": policy.policy_sha256,
        "matches": matches,
        "note": ("仅列出在当前策略下评价为 trusted 的证明；材料命中只"
                 "说明获授权密钥签过的声明里登记了该输入材料"),
    }
