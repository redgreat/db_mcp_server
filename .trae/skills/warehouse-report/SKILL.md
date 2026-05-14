---
name: "warehouse-report"
description: "Generates warehouse reports and uploads to OSS. Invoke when user asks to compose report fields and export result as a downloadable link."
---

# Warehouse Report

Use this skill to generate warehouse BI/operational reports without exposing DB credentials. Compose the source and fields, then call the tool to get an OSS download URL.

Inputs:
- connection_id: integer
- source: object { table, joins?, where?, order_by?, limit? }
- fields: array of { expr|column, alias?, label?, width? }
- output_format: xlsx|csv (default xlsx)
- file_name: optional

Call:
render_report_oss with the above arguments.

Notes:
- Only SELECT is supported.
- Prefer explicit table aliases and fully qualified columns.
- Keep result row count reasonable (use filters/limits) for large datasets. 
