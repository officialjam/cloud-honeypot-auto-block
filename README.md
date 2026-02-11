# Cloud Honeypot Auto-Block (AWS + Terraform)

Portfolio project that detects hostile traffic against a public honeypot, scores attacker IPs, and auto-blocks them in AWS WAF.

## What This Project Demonstrates

- Infrastructure as code with Terraform for a multi-service AWS security pipeline.
- CloudWatch Logs subscription into Lambda for event-driven detections.
- DynamoDB-backed reputation scoring with TTL.
- Automated WAF IP set enforcement once a threshold is reached.
- Practical SOC-style observability with structured Lambda decision logs.

## Architecture Flow

1. Public SSH attempts hit a honeypot EC2 instance.
2. CloudWatch Agent ships honeypot logs to `/honeypot-lab/honeypot`.
3. CloudWatch Logs subscription triggers the `decision-engine` Lambda.
4. Lambda extracts source IPv4, updates score in DynamoDB.
5. When score >= threshold, Lambda writes attacker `/32` into WAF IP set.
6. WAF WebACL blocks that IP at the ALB layer.

## Repository Structure

```text
.
├── README.md
├── docs
│   ├── architecture
│   │   ├── application-composer-template.yaml
│   │   ├── application-composer.md
│   │   └── overview.md
│   └── runbooks
│       ├── deploy.md
│       └── validate.md
├── infra
│   └── terraform
│       ├── src/decision_engine/index.py
│       ├── *.tf
│       └── terraform.tfvars.example
└── .github
    └── workflows
        └── terraform-ci.yml
```

## Quick Start

1. Configure AWS credentials.
2. Copy vars file:

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
```

3. Update `terraform.tfvars` for your account/region.
4. Deploy:

```bash
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

5. Capture outputs:

```bash
terraform output
```

## Documentation

- Architecture overview: `docs/architecture/overview.md`
- Deployment runbook: `docs/runbooks/deploy.md`
- Validation/test runbook: `docs/runbooks/validate.md`
- AWS Application Composer template: `docs/architecture/application-composer-template.yaml`

## AWS Application Composer Diagram

Use `docs/architecture/application-composer-template.yaml` in AWS Application Composer:

- Import the template.
- Auto-arrange/group resources.
- Export a PNG/SVG for your portfolio README.

Detailed steps: `docs/architecture/application-composer.md`.

## Security Notes

- Never commit Terraform state or credential files.
- This repo includes `.gitignore` rules for state/plan/artifact safety.
- Use a remote backend with encryption + locking before production use.

## Cleanup

```bash
cd infra/terraform
terraform destroy
```
