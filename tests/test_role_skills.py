#!/usr/bin/env python3
"""Role skills exist and keep the Orchestrator advisory constraints."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / ".github" / "skills"

ROLE_SKILLS = (
    ("architect-skill", "Architect_Skill"),
    ("test-engineer-skill", "Test_Engineer_Skill"),
    ("cybersec-engineer-skill", "CyberSec_Engineer_Skill"),
    ("product-safety-engineer-skill", "Product_Safety_Engineer_Skill"),
    ("sqa-engineer-skill", "SQA_Engineer_Skill"),
)

REQUIRED_PHRASES = (
    "gh issue create",
    "HOLD/BLOCK",
    "Config1",
    "Host Application",
    "advisory",
    "skills-out/",
)


class RoleSkillTests(unittest.TestCase):
    def test_role_skill_files_use_manager_names(self) -> None:
        for folder, skill_name in ROLE_SKILLS:
            path = SKILLS / folder / "SKILL.md"
            self.assertTrue(path.is_file(), msg=str(path))
            text = path.read_text(encoding="utf-8")
            self.assertIn(skill_name, text)
            self.assertIn("Do not call", text)
            for phrase in REQUIRED_PHRASES:
                self.assertIn(phrase, text, msg=f"{folder}: missing {phrase}")
            self.assertNotIn("Run now", text)

    def test_role_skill_frontmatter_quotes_colons(self) -> None:
        for folder, _skill_name in ROLE_SKILLS:
            text = (SKILLS / folder / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), msg=folder)
            end = text.find("\n---", 3)
            self.assertGreater(end, 0, msg=folder)
            description = ""
            for line in text[4:end].splitlines():
                if line.startswith("description:"):
                    description = line[len("description:") :].strip()
            self.assertTrue(description, msg=folder)
            inner = description.strip('"').strip("'")
            if ": " in inner:
                self.assertTrue(
                    (description.startswith('"') and description.endswith('"'))
                    or (description.startswith("'") and description.endswith("'")),
                    msg=f"{folder} description must be quoted when it contains a colon",
                )

    def test_existing_skills_point_at_role_reviews(self) -> None:
        vendor = (SKILLS / "analyze-vendor-update-impact" / "SKILL.md").read_text(encoding="utf-8")
        pdlc = (SKILLS / "analyze-pdlc-release" / "SKILL.md").read_text(encoding="utf-8")
        for skill_name in (name for _, name in ROLE_SKILLS):
            self.assertIn(skill_name, vendor)
            self.assertIn(skill_name, pdlc)


if __name__ == "__main__":
    unittest.main()
