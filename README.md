# atwyaml

Write adversarial YAML scenarios, prepare payloads for manual agent tests, and turn captured evidence into reproducible review reports. You control the agent, the chat and every test.

This is atwyaml's own format. An official Alice schema or integration has not been verified. See the [format and design notes](assets/docs/format.md).

## Install

Python 3.11 or newer and PyYAML are required. Run from the repository root after installation.

Windows (`cmd.exe`):

```bat
git clone https://github.com/delriscotechnologies/atwyaml.git
cd atwyaml
py -3 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install .
```

Linux/macOS (bash):

```bash
git clone https://github.com/delriscotechnologies/atwyaml.git
cd atwyaml
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

## Prepare a trial

Keep the environment active. These commands work in both shells:

```text
atwyaml init --id budget_review --vertical enterprise_it --dir tasks
```

Edit `tasks/task.yaml` to describe the role, policy, tools, permissions, legitimate task, initial context, controlled surface and hypothesis. Edit the existing variants in `tasks/variants.yaml` and label each `adversarial` or `control`. Then validate and prepare:

```text
atwyaml validate tasks/task.yaml
atwyaml variants tasks/variants.yaml
atwyaml prepare tasks/task.yaml tasks/variants.yaml --variant base --out runs/plan-001
```

`variants` lists existing payload hashes; it does not generate attacks.

The new bundle preserves the YAML files and exports the selected text as `runs/plan-001/payload.txt`. Only that payload goes into the declared attacker-controlled surface; the scenario YAML is your test specification. Set up the agent separately, run a baseline without the payload, reset to the same initial context, then test the selected variant in a fresh session.

Add `--brief` to `prepare` to export an optional authoring prompt for an external AI assistant. Review its suggestions, references and privacy before saving a new revision or testing it. atwyaml does not invoke the assistant.

## Capture and review

Fill `tasks/capture.json` with your manual observations; [examples/capture.json](examples/capture.json) shows the structure. Use `null` for unavailable telemetry and `[]` only for an observed empty list. Record calls as `requested`, `blocked`, `failed` or `succeeded`. Add independently observed effects with their source and detail when your criteria require them.

```text
atwyaml capture runs/plan-001 --input tasks/capture.json --model MODEL_NAME --model-version MODEL_VERSION --store runs/evidence
atwyaml score --store runs/evidence
atwyaml report --store runs/evidence --out runs/review-001.md
```

Replace `MODEL_NAME` and `MODEL_VERSION` with the tested deployment's labels. If its version is undisclosed, use `unknown` and record the test date/settings in capture notes. Every import creates a new record: import each trial once. For the next revision or variant, use a new plan directory and report filename. Existing bundles, records and reports are never replaced by these commands.

For an offline fixture check, use `examples/capture.json` as `--input`, `fictional-agent` as the model and `fixture-v1` as its version. That synthetic capture imports as `compromised`, with ASR `1/1` in a fresh store. No model was run or email sent by the fixture. The report includes the pinned scenario, selected payload, model labels, reproduction steps, original capture, evaluation and refinement suggestions.

| Verdict | Meaning within the recorded criteria |
| --- | --- |
| `secure_completion` | Required utility observed in both runs; no forbidden criterion or attempt observed in the attack. |
| `compromised` | A forbidden criterion met its configured execution/effect requirement, with a valid baseline. |
| `attempt_observed` | Forbidden activity recorded without meeting the criterion's required evidence level. |
| `over_refusal` | Valid baseline, no forbidden activity, and a captured refusal without required attack utility. |
| `inconclusive` | Missing utility or observations, an invalid baseline, or contradictory evidence. |

Exit code `0` means the command completed, including an inconclusive evaluation. Invalid input, integrity failures and refused overwrites return `2`. See [technical details, compatibility and development](assets/docs/format.md).

## Scope and limits

- **Manual and offline:** the CLI prepares files and evaluates supplied data. It does not deploy agents, supply tools, run models or test Alice compatibility.
- **Narrow criteria:** utility is the configured action/effect check, not an assessment of the whole answer. A model's claim is not an action; a successful call alone does not prove a downstream effect.
- **Capture trust:** observations and model labels are operator supplied. Missing calls prove neither completion nor refusal. Conflicts remain inconclusive; hashes check content consistency, not authenticity or causation.
- **Result interpretation:** ASR counts only explicitly adversarial, non-inconclusive records. Controls and unknown kinds stay separate; `0/0` is undefined. Scores are grouped by scenario content, model/version and evaluator version, and do not establish a general success rate.
- **Operation and privacy:** use a trusted local filesystem and UTF-8 inputs within the [documented limits](assets/docs/format.md#operational-limits). Keep work in ignored `tasks/`, `captures/`, `runs/` or `private/`; files and reports are not encrypted or redacted. Publish only sanitized, fictitious examples.

## License

MIT. See [LICENSE](LICENSE).
