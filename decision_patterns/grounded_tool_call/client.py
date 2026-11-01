"""Client for communicating with the local or remote Strands Decider 2B server."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class DeciderClientError(Exception):
    """Raised when the Strands Decider server is unreachable or returns an error."""


class DeciderClient:
    """Client for evaluating System One questions against Strands Decider 2B.

    Connects to the Strands Decider server (by default at DECIDER_URL or http://127.0.0.1:8000)
    and sends structured requests to POST /v1/systemone.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        raw_url = base_url or os.getenv("DECIDER_URL", "http://127.0.0.1:8000")
        self.base_url = raw_url.rstrip("/")
        self.timeout = float(timeout)

    def is_healthy(self) -> bool:
        """Check if the Decider server is running and healthy."""
        url = f"{self.base_url}/health"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "ok"
        except Exception:
            return False

    def ask(
        self,
        state: str | dict[str, Any],
        questions: dict[str, Any],
        model: str = "strands-decider-latest",
    ) -> dict[str, Any]:
        """Execute a System One evaluation on the provided state.

        Args:
            state: The context or state string/dict to evaluate.
            questions: Dictionary mapping question names to Question objects (Noul, Choice, Score).
            model: Model identifier reported in the request.

        Returns:
            Dictionary matching the SystemOneResponse schema:
            {
                "model": str,
                "answers": { "<question_name>": { ... } },
                "usage": { "input_tokens": int, "output_tokens": int },
                "latency_ms": float
            }

        Raises:
            DeciderClientError: If the server is unreachable or request fails.
        """
        url = f"{self.base_url}/v1/systemone"
        payload = {
            "state": state,
            "questions": questions,
            "model": model,
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_body = resp.read().decode("utf-8")
                return json.loads(raw_body)
        except urllib.error.HTTPError as http_err:
            body = ""
            try:
                body = http_err.read().decode("utf-8")
            except Exception:
                pass
            raise DeciderClientError(
                f"Strands Decider server returned HTTP {http_err.code}: {body or http_err.reason}"
            ) from http_err
        except urllib.error.URLError as url_err:
            raise DeciderClientError(
                f"Failed to connect to Strands Decider at {self.base_url}: {url_err.reason}"
            ) from url_err
        except Exception as exc:
            raise DeciderClientError(
                f"Unexpected error communicating with Strands Decider: {exc}"
            ) from exc

    def ask_noul(
        self,
        state: str | dict[str, Any],
        instructions: str,
        criteria: dict[str, str] | None = None,
        question_id: str = "q",
    ) -> float:
        """Convenience method for a single binary yes/no question.

        Returns:
            Float probability in [0.0, 1.0] indicating likelihood that the answer is true.
        """
        question_payload: dict[str, Any] = {
            "type": "noul",
            "instructions": instructions,
        }
        if criteria:
            question_payload["criteria"] = criteria

        response = self.ask(state=state, questions={question_id: question_payload})
        answer = response.get("answers", {}).get(question_id, {})
        if "noul" in answer:
            return float(answer["noul"])
        raise DeciderClientError(f"Malformed noul response from server: {response}")
