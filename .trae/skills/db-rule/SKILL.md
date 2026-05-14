---
name: "db-rule"
description: "Generates RULE.md for a database by analyzing schema and flows. Invoke when user asks to build/update database rules for reporting."
---

# Database Rule Author

Generates a RULE.md for a target database as structured guidance for report generation and data modeling.

Inputs:
- connection_id: integer
- database: optional string (defaults to connection database)
- save_to_project: bool (default true) — writes to rules/<db>/RULE.md
- save_to_admin: bool (default true) — persists to admin DB db_rules
- project_base: optional project root override
- title/version/tags: optional metadata

Call:
generate_db_rule with the above arguments.

Notes:
- Only introspects metadata (no data mutation).
- Output is human-editable and intended as long-lived memory for the skill.
