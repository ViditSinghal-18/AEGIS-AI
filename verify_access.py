"""Confirm AWS identity and that Bedrock invoke is reachable."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import AWS_REGION, BEDROCK_MODEL_ID


def main() -> int:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        print("boto3 is not installed. Run: pip install -r requirements.txt")
        return 1

    print(f"Region: {AWS_REGION}")
    print(f"Bedrock model: {BEDROCK_MODEL_ID}")

    try:
        sts = boto3.client("sts", region_name=AWS_REGION)
        ident = sts.get_caller_identity()
        print(f"STS Account: {ident.get('Account')} ARN: {ident.get('Arn')}")
    except (BotoCoreError, ClientError) as exc:
        print(f"STS check skipped or failed ({exc.__class__.__name__}): {exc}")
        print("That can be OK if your IAM key is scoped only to Bedrock.")

    try:
        client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
        response = client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "Reply with the single word pong."}]}],
            inferenceConfig={"maxTokens": 16, "temperature": 0.0},
        )
        parts = response.get("output", {}).get("message", {}).get("content", [])
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p)
        print(f"Bedrock invoke OK. Model said: {text!r}")
        return 0
    except (BotoCoreError, ClientError) as exc:
        print(f"Bedrock invoke FAILED: {exc}")
        print("Check: region, model access in Bedrock console, and BEDROCK_MODEL_ID.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
