# netconfig-audit-agent

An AI security agent that audits Cisco IOS configurations for misconfigurations, running entirely in GitHub Actions with no stored API keys.

Push a configuration file to `configs/` and the pipeline:

1. Runs deterministic rules that catch known misconfigurations (Telnet on VTY lines, default SNMP communities, `permit ip any any`, weak password types, missing logging, and more).
2. Redacts every password, key and community string from the configuration.
3. Sends the redacted configuration and the rule findings to Claude, which adds issues the rules cannot see, questions likely false positives and prioritises the fixes.
4. Publishes a Markdown report in the workflow run summary and uploads `report.md` and `findings.json` as artifacts.

This is the first component of a larger project: a set of agents that detect threats and misconfigurations, and an orchestrator that can quarantine a compromised asset without taking the service down.

## How it works

```
configs/*.cfg
     |
     v
rules.py  ---------------->  rule findings
     |                            |
     v                            v
redaction  -->  Claude review (additional findings, false positives, priorities)
                                  |
                                  v
                     report.md + findings.json
```

The rules are the baseline and keep working with no API access. The AI review adds judgement on top. If the API call fails, or the answer is truncated (`stop_reason` is `max_tokens`) or is not valid JSON, the review counts as failed and the report still contains the rule findings. The run then exits with status 1 and prints a GitHub Actions error annotation naming the file, so a failed AI review never looks like a healthy run. Rules-only mode (no credentials, or `--no-llm`) exits 0.

## Security design

- **No static secrets.** The workflow authenticates to the Claude API with Workload Identity Federation: GitHub issues a short-lived OIDC token for the job, and Anthropic exchanges it for an access token that expires in minutes.
- **Secrets never leave the runner.** Passwords, hashes, keys and SNMP communities are replaced with `<redacted>` before the configuration is sent to the model or written to a report.
- **Configuration text is treated as untrusted input.** The system prompt instructs the model to analyse the file and never follow instructions inside it.
- **Narrow trust.** The federation rule only accepts tokens from this repository's `main` branch, and the workflow does not run on pull requests from forks.
- **Lab data only.** The sample configurations are synthetic. Do not commit configurations from production or employer devices.

## Repository layout

| Path | Purpose |
|---|---|
| `audit_agent.py` | Orchestrates rules, redaction, AI review and reporting |
| `rules.py` | Deterministic Cisco IOS checks (IOS-001 to IOS-020) |
| `configs/lab-r1-vulnerable.cfg` | Synthetic router with intentional misconfigurations |
| `configs/lab-r2-hardened.cfg` | Synthetic router with the hardened baseline |
| `configs/lab-sw1-access.cfg` | Synthetic access-layer switch, mostly reasonable, with a few intentional misconfigurations |
| `tests/test_rules.py` | Unit tests for rules, redaction and response parsing |
| `.github/workflows/config-audit.yml` | The pipeline |

## Setup

### 1. Connect the repository to the Claude Console

In the Claude Console, open **Settings > Workload identity**, select **Connect workload** and choose the **GitHub Actions** tile. Use these values:

| Field | Value |
|---|---|
| Issuer URL | `https://token.actions.githubusercontent.com` |
| Audience | `https://api.anthropic.com` |
| Subject prefix | `repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main` (see below) |
| Claim `repository_owner` | `<owner>` |
| Workspace | the workspace that should receive the traffic |
| OAuth scope | `workspace:developer` |

The wizard creates a service account and a federation rule. Record the `svac_...` and `fdrl_...` IDs.

#### Getting the subject right

The subject must match the `sub` claim of the GitHub OIDC token exactly. A mismatch is the most common reason for `401 Authentication failed`.

Repositories created after July 15, 2026 use the immutable subject format, which includes the numeric owner and repository IDs:

```
repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main
```

Older repositories use the short format `repo:OWNER/REPO:ref:refs/heads/main`. A rule written in the short format does not match a token from a newer repository.

Get both IDs with the GitHub CLI:

```
gh api users/OWNER --jq .id          # OWNER_ID (use orgs/OWNER for an organization)
gh api repos/OWNER/REPO --jq .id     # REPO_ID
```

The surest method is not to build the subject by hand. Let one run fail, open the failed attempt in the authentication events on the **Workload identity** page of the Console, and copy its `sub` value into the rule.

The rule only accepts `push` events on `main`. A run started manually with `workflow_dispatch` carries a different event and is rejected, which is why the workflow has no manual trigger.

### 2. Add repository variables

In GitHub, open **Settings > Secrets and variables > Actions > Variables** and add:

| Variable | Value |
|---|---|
| `ANTHROPIC_FEDERATION_RULE_ID` | `fdrl_...` |
| `ANTHROPIC_SERVICE_ACCOUNT_ID` | `svac_...` |
| `ANTHROPIC_ORGANIZATION_ID` | organization ID from the Console |
| `ANTHROPIC_WORKSPACE_ID` | `wrkspc_...` |

These are identifiers, not secrets, so they are stored as variables. Optional variables: `AUDIT_MODEL` (default `claude-sonnet-5-5`) and `FAIL_ON` (`none`, `low`, `medium`, `high` or `critical`; default `none`).

### 3. Run it

Push to `main`. Open the run to read the report in the summary.

To run the audit again without a new commit, re-run the last push-triggered run. It keeps the `push` event and requests a fresh OIDC token:

```
gh run rerun RUN_ID
```

The workflow has no manual trigger (`workflow_dispatch`) on purpose: the rule only accepts `push` events, so a manually started run would fail the AI review with 401. Note that `gh run rerun --failed` only works when a job failed.

Until the variables are set, the pipeline runs in rules-only mode.

## Run locally (rules only)

```
python audit_agent.py configs/ --no-llm
python -m unittest discover -s tests -v
```

## Troubleshooting

A failed token exchange always returns `401 Authentication failed`. The reason is shown in the authentication events on the **Workload identity** page of the Console; search for the `request_id` printed in the error. Usual causes:

- The subject in the rule does not match the token. Check the immutable format with the numeric IDs (see "Getting the subject right") and copy the `sub` from the failed attempt.
- The run was not triggered by a push (for example a `workflow_dispatch` trigger was added back). Use `gh run rerun RUN_ID` on a push-triggered run.

## Roadmap

- FortiGate configuration support
- Threat detection agent over SIEM alerts
- Risk scoring agent (attack paths and trends)
- Orchestrator with automated quarantine and human approval for critical assets
