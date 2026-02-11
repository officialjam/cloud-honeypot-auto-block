import base64
import gzip
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

ddb = boto3.client("dynamodb")

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ----------------------------
# Required env vars
# ----------------------------
TABLE_NAME = os.environ["IP_TABLE_NAME"]
WAF_IPSET_ARN = os.environ["WAF_IPSET_ARN"]

# ----------------------------
# Optional env vars (SOC controls)
# ----------------------------
TTL_SECONDS = int(os.environ.get("TTL_SECONDS", "86400"))  # 1 day
SCORE_INCREMENT = int(os.environ.get("SCORE_INCREMENT", "1"))  # score per event
BLOCK_THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "7"))  # block at/above score
ALLOWLIST_RAW = json.loads(os.environ.get("ALLOWLIST_IPS", "[]"))
AUTO_BLOCK_ENABLED = os.environ.get("AUTO_BLOCK_ENABLED", "true").lower() == "true"
MAX_IPSET_SIZE = int(os.environ.get("MAX_IPSET_SIZE", "5000"))  # safety cap
MAX_WAF_RETRIES = max(1, int(os.environ.get("MAX_WAF_RETRIES", "4")))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_allowlist_networks(entries: List[str]) -> List[ipaddress.IPv4Network]:
    networks: List[ipaddress.IPv4Network] = []
    for entry in entries:
        try:
            candidate = entry if "/" in entry else f"{entry}/32"
            network = ipaddress.ip_network(candidate, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                networks.append(network)
            else:
                print(
                    json.dumps(
                        {
                            "type": "CONFIG_WARNING",
                            "warning": "UNSUPPORTED_ALLOWLIST_ENTRY",
                            "entry": entry,
                        }
                    )
                )
        except ValueError:
            print(
                json.dumps(
                    {
                        "type": "CONFIG_WARNING",
                        "warning": "INVALID_ALLOWLIST_ENTRY",
                        "entry": entry,
                    }
                )
            )
    return networks


ALLOWLIST_NETWORKS = parse_allowlist_networks(ALLOWLIST_RAW)


def extract_ipv4s(msg: str) -> List[str]:
    """
    Defensive extraction: find IPv4 patterns in a log line and discard invalid octets.
    """
    matches = IPV4_PATTERN.findall(msg)
    valid: List[str] = []
    for ip in matches:
        try:
            parsed = ipaddress.ip_address(ip)
            if isinstance(parsed, ipaddress.IPv4Address):
                valid.append(ip)
        except ValueError:
            continue
    return valid


def select_actionable_ip(candidates: List[str]) -> str | None:
    """
    Pick the first globally-routable IPv4 from extracted candidates.
    This avoids self/listener addresses (e.g., 0.0.0.0) from daemon startup logs.
    """
    for ip in candidates:
        parsed = ipaddress.ip_address(ip)
        if isinstance(parsed, ipaddress.IPv4Address) and parsed.is_global:
            return ip
    return None


def normalize_to_cidr(ip: str) -> str:
    network = ipaddress.ip_network(ip if "/" in ip else f"{ip}/32", strict=False)
    return str(network)


def is_allowlisted(ip_or_cidr: str) -> bool:
    try:
        host = ip_or_cidr.split("/")[0]
        candidate_ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    if not isinstance(candidate_ip, ipaddress.IPv4Address):
        return False

    return any(candidate_ip in network for network in ALLOWLIST_NETWORKS)


def parse_ipset_arn(arn: str) -> Tuple[str, str, str, str]:
    """
    WAFv2 IPSet ARN examples:
      arn:aws:wafv2:eu-west-1:123456789012:regional/ipset/name/id
      arn:aws:wafv2:us-east-1:123456789012:global/ipset/name/id
    Returns: (region, scope, name, ipset_id)
    """
    parts = arn.split(":")
    if len(parts) < 6:
        raise ValueError(f"Invalid WAF IPSet ARN: {arn}")

    region = parts[3]
    rest_parts = parts[5].split("/")
    if len(rest_parts) < 4:
        raise ValueError(f"Invalid WAF IPSet ARN path: {arn}")

    scope_token = rest_parts[0].upper()  # REGIONAL or GLOBAL
    scope = "CLOUDFRONT" if scope_token == "GLOBAL" else scope_token
    if scope not in {"REGIONAL", "CLOUDFRONT"}:
        raise ValueError(f"Unsupported WAF scope in ARN: {arn}")

    name = rest_parts[2]
    ipset_id = rest_parts[3]
    return region, scope, name, ipset_id


def get_ipset_state() -> Tuple[Any, str, str, str, List[str], str]:
    """
    Returns: (waf_client, scope, name, ipset_id, addresses, lock_token)
    """
    region, scope, name, ipset_id = parse_ipset_arn(WAF_IPSET_ARN)
    waf = boto3.client("wafv2", region_name=region)
    resp = waf.get_ip_set(Name=name, Scope=scope, Id=ipset_id)
    addresses = resp["IPSet"]["Addresses"]
    lock_token = resp["LockToken"]
    return waf, scope, name, ipset_id, addresses, lock_token


def update_ipset_add_address(ip: str) -> Dict[str, str]:
    """
    Adds IP (/32) to WAF IPSet if not present, respecting allowlist + max size.
    Retries optimistic lock conflicts caused by concurrent Lambda invocations.
    """
    cidr = normalize_to_cidr(ip)

    if is_allowlisted(cidr):
        return {"action": "SKIP", "reason": "ALLOWLISTED", "cidr": cidr}

    for attempt in range(1, MAX_WAF_RETRIES + 1):
        waf, scope, name, ipset_id, addresses, lock_token = get_ipset_state()

        if cidr in addresses:
            return {"action": "SKIP", "reason": "ALREADY_PRESENT", "cidr": cidr}

        if len(addresses) >= MAX_IPSET_SIZE:
            return {"action": "SKIP", "reason": "IPSET_AT_CAP", "cidr": cidr}

        new_addresses = addresses + [cidr]
        try:
            waf.update_ip_set(
                Name=name,
                Scope=scope,
                Id=ipset_id,
                LockToken=lock_token,
                Addresses=new_addresses,
            )
            return {"action": "BLOCK", "reason": "THRESHOLD_MET", "cidr": cidr}
        except waf.exceptions.WAFOptimisticLockException:
            if attempt == MAX_WAF_RETRIES:
                raise
            time.sleep(min(0.25 * (2 ** (attempt - 1)), 2.0))
        except ClientError as ex:
            code = ex.response.get("Error", {}).get("Code", "")
            if code != "WAFOptimisticLockException" or attempt == MAX_WAF_RETRIES:
                raise
            time.sleep(min(0.25 * (2 ** (attempt - 1)), 2.0))

    raise RuntimeError("Unexpected retry loop exit while updating WAF IPSet")


def update_reputation(ip: str) -> int:
    """
    Atomically increments score and updates timestamps/ttl.
    Returns updated score.
    """
    ts = int(time.time())
    ttl = ts + TTL_SECONDS
    now = now_iso()

    resp = ddb.update_item(
        TableName=TABLE_NAME,
        Key={"ip": {"S": ip}},
        UpdateExpression=(
            "SET first_seen = if_not_exists(first_seen, :fs), "
            "last_seen = :ls, "
            "#ttl = :ttl "
            "ADD score :inc"
        ),
        ExpressionAttributeNames={
            "#ttl": "ttl",
        },
        ExpressionAttributeValues={
            ":fs": {"S": now},
            ":ls": {"S": now},
            ":ttl": {"N": str(ttl)},
            ":inc": {"N": str(SCORE_INCREMENT)},
        },
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["score"]["N"])


def handler(event, context):
    # CloudWatch Logs subscription -> event["awslogs"]["data"] is base64(gzip(json))
    encoded = event.get("awslogs", {}).get("data")
    if not encoded:
        print(
            json.dumps(
                {
                    "type": "EVENT_ERROR",
                    "reason": "MISSING_AWSLOGS_DATA",
                }
            )
        )
        return {"ok": False, "reason": "MISSING_AWSLOGS_DATA"}

    data = base64.b64decode(encoded)
    payload = gzip.decompress(data)
    logs = json.loads(payload)

    log_events = logs.get("logEvents", [])
    processed = 0
    reputation_updates = 0
    blocks = 0
    skipped_allowlist = 0
    skipped_disabled = 0
    block_cache: Dict[str, Dict[str, str]] = {}
    blocked_cidrs: set[str] = set()

    # SOC-style audit header
    print(
        json.dumps(
            {
                "type": "SOC_PIPELINE_START",
                "auto_block_enabled": AUTO_BLOCK_ENABLED,
                "block_threshold": BLOCK_THRESHOLD,
                "score_increment": SCORE_INCREMENT,
                "ttl_seconds": TTL_SECONDS,
                "max_ipset_size": MAX_IPSET_SIZE,
                "max_waf_retries": MAX_WAF_RETRIES,
                "allowlist_count": len(ALLOWLIST_NETWORKS),
                "batch_events": len(log_events),
            }
        )
    )

    for e in log_events:
        processed += 1
        message = e.get("message", "")
        ips = extract_ipv4s(message)

        if not ips:
            continue

        ip = select_actionable_ip(ips)
        if not ip:
            continue

        if is_allowlisted(ip):
            skipped_allowlist += 1
            continue

        # Update DynamoDB reputation
        score = update_reputation(ip)
        reputation_updates += 1

        # Decide block
        if score < BLOCK_THRESHOLD:
            # SOC signal: observed but not blocked
            print(
                json.dumps(
                    {
                        "type": "IP_OBSERVED",
                        "ip": ip,
                        "score": score,
                        "decision": "NO_BLOCK",
                        "reason": "BELOW_THRESHOLD",
                    }
                )
            )
            continue

        if not AUTO_BLOCK_ENABLED:
            skipped_disabled += 1
            print(
                json.dumps(
                    {
                        "type": "IP_DECISION",
                        "ip": ip,
                        "score": score,
                        "decision": "NO_BLOCK",
                        "reason": "AUTO_BLOCK_DISABLED",
                    }
                )
            )
            continue

        # Enforce via WAF IPSet. Reuse result for repeated IPs in the same batch.
        try:
            if ip not in block_cache:
                block_cache[ip] = update_ipset_add_address(ip)

            result = block_cache[ip]
            decision = result.get("action", "SKIP")
            reason = result.get("reason", "UNKNOWN")
            cidr = result.get("cidr", "")

            if decision == "BLOCK" and cidr not in blocked_cidrs:
                blocks += 1
                blocked_cidrs.add(cidr)

            print(
                json.dumps(
                    {
                        "type": "IP_DECISION",
                        "ip": ip,
                        "score": score,
                        "decision": decision,
                        "reason": reason,
                        "cidr": cidr,
                    }
                )
            )
        except Exception as ex:
            # SOC signal: enforcement failure
            print(
                json.dumps(
                    {
                        "type": "ENFORCEMENT_ERROR",
                        "ip": ip,
                        "score": score,
                        "error": str(ex),
                    }
                )
            )

    # SOC-style summary footer
    summary = {
        "type": "SOC_PIPELINE_SUMMARY",
        "processed_events": processed,
        "reputation_updates": reputation_updates,
        "blocks": blocks,
        "skipped_allowlist": skipped_allowlist,
        "skipped_disabled": skipped_disabled,
    }
    print(json.dumps(summary))
    return {"ok": True, **summary}
