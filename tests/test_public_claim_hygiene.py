"""Regression checks for Standard v3 public claim hygiene."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CLAIM_DOCS = (
    ROOT / "docs" / "SHOWCASE.md",
    ROOT / "docs" / "COMPETITION_COMPARISON.md",
)


def test_public_claim_docs_do_not_use_unaccepted_superiority_claims():
    forbidden_phrases = (
        "mission accomplished",
        "the ultimate privacy system",
        "absolutely destroys",
        "destroys every competitor",
        "most advanced, comprehensive, and powerful privacy-first system ever created",
        "what makes this unstoppable",
        "god tier",
        "the competition can't compare",
        "no competitor offers even 50%",
        "most competitors offer < 20%",
        "superior in every way",
        "undisputed champion",
        "98/100",
        "72% better",
        "zero telemetry (impossible to enable)",
    )

    for doc_path in PUBLIC_CLAIM_DOCS:
        content = doc_path.read_text(encoding="utf-8").lower()
        for phrase in forbidden_phrases:
            assert phrase not in content, f"{doc_path} contains overclaim: {phrase}"


def test_public_claim_docs_point_to_standard_v3_acceptance_matrix():
    required_reference = "docs/operations/README_CLAIM_ACCEPTANCE.md"

    for doc_path in PUBLIC_CLAIM_DOCS:
        content = doc_path.read_text(encoding="utf-8")
        assert "Standard v3" in content
        assert required_reference in content
