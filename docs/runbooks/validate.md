# Validation Runbook

## Goal

Prove that logs are ingested, detections are scored, and WAF blocks at threshold.

## 1. Confirm CloudWatch Log Streams

```bash
aws logs describe-log-streams \
  --log-group-name /honeypot-lab/honeypot \
  --order-by LastEventTime \
  --descending
```

Expect streams like:

- `<instance-id>-bootstrap`
- `<instance-id>-secure`

## 2. Trigger SSH Events

```bash
HONEYPOT_IP="<terraform output honeypot_public_ip>"
for i in $(seq 1 8); do
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 invaliduser@"$HONEYPOT_IP" "exit" || true
  sleep 1
done
```

## 3. Inspect Decision Logs

```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/honeypot-lab-decision-engine \
  --limit 200
```

Expect events:

- `SOC_PIPELINE_START`
- `IP_OBSERVED`
- `IP_DECISION` with `BLOCK` when threshold reached
- `SOC_PIPELINE_SUMMARY`

## 4. Verify Reputation Table

```bash
aws dynamodb scan --table-name honeypot-lab-ip-reputation
```

Expect `score` increments for source IP.

## 5. Verify WAF Blocklist

```bash
aws wafv2 get-ip-set \
  --name honeypot-lab-blocklist \
  --scope REGIONAL \
  --id <ipset-id>
```

Expect source IP `/32` in `Addresses` once threshold is met.

## 6. Verify ALB Enforcement

```bash
ALB_DNS="<terraform output alb_dns_name>"
curl -i "http://$ALB_DNS"
```

Expect `403` if your current IP has been blocked.
