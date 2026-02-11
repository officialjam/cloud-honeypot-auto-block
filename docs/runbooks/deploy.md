# Deployment Runbook

## Prerequisites

- Terraform `>= 1.5`
- AWS CLI v2 configured
- AWS credentials with permissions for EC2, IAM, Lambda, CloudWatch, DynamoDB, WAFv2, ELBv2

## Steps

1. Enter Terraform directory:

```bash
cd infra/terraform
```

2. Create a vars file:

```bash
cp terraform.tfvars.example terraform.tfvars
```

3. Update `terraform.tfvars` values for your environment.

4. Initialize and deploy:

```bash
terraform init
terraform fmt -recursive
terraform validate
terraform plan -out tfplan
terraform apply tfplan
```

5. Capture outputs:

```bash
terraform output
```

## Expected Outputs

- `honeypot_public_ip`
- `alb_dns_name`
- `cloudwatch_log_group`
- `waf_ipset_arn`
- `waf_web_acl_arn`

## Cleanup

```bash
terraform destroy
```
