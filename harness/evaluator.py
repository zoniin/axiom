import argparse
import re
import sys
import yaml

BLOCK_PATTERNS = [r"!\[[^\]]*\]\([^\)]*\)", r"<img\b", r"data:", r"javascript:", r"\d{3}-\d{2}-\d{4}"]
ESCALATE_PATTERNS = [r"ignore previous", r"reveal .*ssn", r"system prompt", r"developer message"]


def evaluate(input_text: str, proposed_output: str, proposed_sinks: list) -> str:
    combined = f"{input_text}\n{proposed_output}"
    if proposed_sinks:
        for sink in proposed_sinks:
            if sink.get("type") in {"url", "webhook", "email", "export"}:
                return "block"
    if any(re.search(p, combined, re.I) for p in BLOCK_PATTERNS):
        return "block"
    if any(re.search(p, combined, re.I) for p in ESCALATE_PATTERNS):
        return "escalate"
    return "allow"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", required=True)
    args = parser.parse_args()

    with open(args.scenarios, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    failures = 0
    for scenario in data["scenarios"]:
        got = evaluate(
            scenario.get("input", ""),
            scenario.get("proposed_output", ""),
            scenario.get("proposed_sinks", []),
        )
        expected = scenario["expected_decision"]
        ok = got == expected
        print(f"{scenario['id']}: expected={expected} got={got} {'PASS' if ok else 'FAIL'}")
        failures += 0 if ok else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
