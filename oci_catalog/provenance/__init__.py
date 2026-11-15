"""离线构建证明接入子系统（DSSE 信封 + in-toto/SLSA 声明 + 本地信任策略）。

模块划分：

* :mod:`oci_catalog.provenance.jsonutil` —— 严格 JSON（重复键带路径拒绝）
* :mod:`oci_catalog.provenance.dsse`    —— DSSE 信封解析、PAE、Ed25519 验签
* :mod:`oci_catalog.provenance.intoto`  —— in-toto Statement v1 / SLSA v1 解析
* :mod:`oci_catalog.provenance.policy`  —— 本地信任策略（公钥登记 + 授权规则）
* :mod:`oci_catalog.provenance.store`   —— 独立 SQLite 证据库与幂等导入
* :mod:`oci_catalog.provenance.queries` —— 证据评价与镜像/材料两类查询
* :mod:`oci_catalog.provenance.provenance_cli` —— 命令行入口

全程本地：不连接透明日志、证书服务或 registry；密码运算全部委托
``cryptography`` 的 Ed25519 实现。本子系统只读访问目录库，证据落在独立
SQLite 库，不写目录/SBOM/文件视图/关系库。
"""

from .dsse import (
    IN_TOTO_PAYLOAD_TYPE,
    ParsedEnvelope,
    Signature,
    b64decode_strict,
    ed25519_verify,
    pae,
    parse_envelope,
)
from .intoto import (
    SLSA_PREDICATE_TYPE,
    STATEMENT_TYPE,
    Material,
    ParsedStatement,
    Subject,
    parse_statement,
)
from .jsonutil import Diagnostic, DuplicateKeyError, StrictJSONError
from .policy import (
    Policy,
    PolicyError,
    Rule,
    key_fingerprint,
    load_policy,
)
from .queries import (
    REASON_NO_MATCHING_RULE,
    REASON_NO_VALID_SIGNATURES,
    REASON_THRESHOLD_MET,
    REASON_THRESHOLD_NOT_MET,
    TRUSTED,
    UNTRUSTED,
    Evaluation,
    evaluate_evidence,
    query_image_provenance,
    query_material_images,
)
from .store import (
    BINDING_NOT_IMAGE,
    BINDING_SUBJECT_MISMATCH,
    BINDING_UNKNOWN_DIGEST,
    DUPLICATE_SKIPPED,
    FAILED,
    IMPORTED,
    ImportResult,
    ProvenanceStore,
)

__all__ = [
    # DSSE
    "IN_TOTO_PAYLOAD_TYPE", "ParsedEnvelope", "Signature", "parse_envelope",
    "pae", "ed25519_verify", "b64decode_strict",
    # in-toto / SLSA
    "STATEMENT_TYPE", "SLSA_PREDICATE_TYPE", "ParsedStatement", "Subject",
    "Material", "parse_statement",
    # 严格 JSON 与诊断
    "Diagnostic", "StrictJSONError", "DuplicateKeyError",
    # 策略
    "Policy", "PolicyError", "Rule", "load_policy", "key_fingerprint",
    # 存储
    "ProvenanceStore", "ImportResult", "IMPORTED", "DUPLICATE_SKIPPED",
    "FAILED", "BINDING_NOT_IMAGE", "BINDING_UNKNOWN_DIGEST",
    "BINDING_SUBJECT_MISMATCH",
    # 评价与查询
    "evaluate_evidence", "Evaluation", "TRUSTED", "UNTRUSTED",
    "REASON_THRESHOLD_MET", "REASON_NO_MATCHING_RULE",
    "REASON_NO_VALID_SIGNATURES", "REASON_THRESHOLD_NOT_MET",
    "query_image_provenance", "query_material_images",
]
