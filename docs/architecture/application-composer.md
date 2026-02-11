# AWS Application Composer Diagram Guide

## Goal

Generate a clean visual architecture diagram from this project for portfolio use.

## Source Template

- `docs/architecture/application-composer-template.yaml`

## Steps

1. Open AWS Console in the same region as your stack.
2. Go to **Application Composer**.
3. Create a new project and select **Import template**.
4. Upload `docs/architecture/application-composer-template.yaml`.
5. Let Composer auto-place resources, then group into lanes:
   - Ingestion (`CloudWatch Logs`)
   - Detection (`Lambda` + `DynamoDB`)
   - Enforcement (`WAF`)
   - Protected App (`ALB` + web target)
6. Export diagram as PNG or SVG.
7. Save it in the repo as `docs/architecture/application-composer-diagram.png`.
8. Reference it in `README.md`.

## Suggested Caption

"Automated honeypot response pipeline: CloudWatch -> Lambda scoring -> DynamoDB reputation -> WAF auto-block -> ALB protection."
