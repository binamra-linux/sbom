import json
import sys
import os
import urllib.request

def load_grype_results(path="grype-results.json"):
    with open(path) as f:
        raw = f.read()
    print(f"Raw grype-results.json size: {len(raw)} bytes")
    data = json.loads(raw)
    matches = data.get("matches", [])
    print(f"Matches found in JSON: {len(matches)}")
    vulns = []
    for m in matches:
        v = m.get("vulnerability", {})
        a = m.get("artifact", {})
        vulns.append({
            "id": v.get("id"),
            "severity": v.get("severity"),
            "package": a.get("name"),
            "version": a.get("version"),
            "fixed_in": v.get("fix", {}).get("versions", []),
            "description": v.get("description", "")[:300]
        })
    return vulns

def call_claude(vulns):
    api_key = os.environ["GROQ_API_KEY"]
    vuln_text = json.dumps(vulns, indent=2)

    prompt = f"""You are a security engineer reviewing vulnerability scan results for a Node.js web application.

Here are the vulnerabilities found by Grype:

{vuln_text}

Please provide a triage report with the following sections:

## Summary
One paragraph: how many vulns, overall risk level, and the single most urgent issue.

## Top 3 Priorities
For each, explain: what the vulnerability actually does, why it matters for a Node.js web app specifically, and the exact fix (package upgrade version).

## Safe to Deprioritize
List any CVEs that are low risk in this context and briefly explain why.

## Recommended Actions
Numbered list of concrete next steps in priority order.

Be specific and practical. Avoid generic security advice."""

    body = json.dumps({
        "model": "mixtral-8x7b-32768",
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"API Error: {e.code} - {error_body}", file=sys.stderr)
        raise

def post_pr_comment(report):
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr_number = os.environ.get("PR_NUMBER")

    if not all([token, repo, pr_number]):
        print("Not a PR context — printing report only:")
        print(report)
        return

    body = json.dumps({
        "body": f"## SBOM Security Triage Report\n\n{report}"
    }).encode()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json"
        }
    )
    urllib.request.urlopen(req)
    print("Report posted to PR.")

if __name__ == "__main__":
    print("Loading Grype results...")
    vulns = load_grype_results()

    if len(vulns) == 0:
        print("No vulnerabilities found — skipping Claude triage.")
        print("Check that package.json has old dependency versions.")
        sys.exit(0)

    print(f"Found {len(vulns)} vulnerabilities. Sending to Claude...")
    report = call_claude(vulns)
    print("Report generated:")
    print(report)
    post_pr_comment(report)