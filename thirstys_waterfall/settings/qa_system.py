"""Q/A system with local helper encryption."""

import logging
from typing import Dict, Any, List
import time


class QASystem:
    """Question and Answer system"""

    def __init__(self, god_tier_encryption):
        self.logger = logging.getLogger(__name__)
        self.god_tier_encryption = god_tier_encryption

        self.qa_database = [
            {
                "id": "q1",
                "category": "privacy",
                "question": "How does local helper encryption work?",
                "answer": (
                    "Local helper encryption uses layered classical primitives and "
                    "remains separate from accepted end-to-end or post-quantum claims."
                ),
            },
            {
                "id": "q2",
                "category": "security",
                "question": "What is the kill switch?",
                "answer": (
                    "A configured kill-switch backend can attempt to block traffic "
                    "when the VPN connection drops; acceptance requires backend "
                    "execution evidence."
                ),
            },
            {
                "id": "q3",
                "category": "ads",
                "question": "How aggressive is ad blocking?",
                "answer": (
                    "HOLY WAR mode applies the configured blocking rules to ads, "
                    "trackers, pop-ups, redirects, and autoplay media. Results depend "
                    "on the active backend and rule coverage."
                ),
            },
        ]

        self.user_questions: List[Dict[str, Any]] = []

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search Q/A database"""
        query_lower = query.lower()
        return [
            qa
            for qa in self.qa_database
            if query_lower in qa["question"].lower()
            or query_lower in qa["answer"].lower()
        ]

    def submit_question(
        self, question: str, category: str = "general"
    ) -> Dict[str, Any]:
        """Submit a question (encrypted)"""
        encrypted_q = self.god_tier_encryption.encrypt_god_tier(question.encode())
        submission = {
            "id": f"uq_{len(self.user_questions)}",
            "encrypted_question": encrypted_q,
            "timestamp": time.time(),
            "local_helper_encrypted": True,
            "encryption_accepted": False,
        }
        self.user_questions.append(submission)
        return {"status": "submitted", "id": submission["id"]}
