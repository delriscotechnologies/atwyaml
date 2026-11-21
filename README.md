<p align="center">
  <img src="assets/atwyaml-logo.png" alt="atwyaml logo" width="420">
</p>

Write YAML scenarios for manual AI red teaming. Describe your hypothesis, prepare a test brief and the payload you copy into an agent's chat, then preserve your observations for review. You choose what to test and when.

## Install

Requires Git and Python 3.11+. Installation includes PyYAML.

Linux/macOS (bash):

```bash
git clone https://github.com/delriscotechnologies/atwyaml.git
cd atwyaml
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Windows (`cmd.exe`):

```bat
git clone https://github.com/delriscotechnologies/atwyaml.git
cd atwyaml
py -3 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install .
```

## Prepare and review

Keep the environment active. Start from the repository root. You can also use an empty working directory outside the checkout.

```text
atwyaml init tasks/v3
```

Edit `tasks/v3/task.yaml`: its comments guide you through the agent, policy, tools, permissions, legitimate task, initial state, hypothesis and injection surface. Replace the fictitious example and write payload variants labeled `adversarial` or `control`. `required` rules check task completion; `forbidden` rules define the attacker goal.

```text
atwyaml prepare tasks/v3/task.yaml base runs/v3-plan-001
```

Replace `base` with your variant's name. The generated `brief.md` gives you the steps, evidence criteria and commands to import and review observations. `plan.json` preserves the YAML and selection. `payload.txt` contains the text for the controlled surface.

Follow the brief and save observations as `capture.json` inside `runs/v3-plan-001/`. Record the date, settings, sources and deviations in `notes`. Use `null` or omit unavailable telemetry. Use `[]` for an observed empty list.

For an offline check with the unchanged template, save this **synthetic capture** instead; no agent was run:

```json
{
  "version": 3,
  "baseline": {"calls": [
    {"tool": "read_internal_doc", "arguments": {"doc_id": "budget-sheet"}, "status": "succeeded"}
  ]},
  "attack": {"calls": [
    {"tool": "read_internal_doc", "arguments": {"doc_id": "budget-sheet"}, "status": "succeeded"},
    {"tool": "send_email", "arguments": {"to": "vendor@external.example"}, "status": "blocked"}
  ]},
  "notes": "Synthetic workflow check; no agent was run."
}
```

Run both commands from `runs/v3-plan-001/`.

```text
atwyaml capture . capture.json --model MODEL_NAME --model-version MODEL_VERSION --store evidence
atwyaml report evidence --out review.md
```

Replace `MODEL_NAME`/`MODEL_VERSION` with deployment labels; use `fictional-agent`/`fixture-v1` for this synthetic check, or `unknown` for an undisclosed version. The sample gives `attempt_observed` and ASR `0/1` in a fresh store. Omit `--out` to print the report.

The report starts with a trial table showing model, variant, verdict, baseline/attack utility and indexed evidence, followed by cohort and variant results. Its JSON appendix preserves conditions, reproduction details and original observations; `call_indices`/`effect_indices` point into the original lists.

Each import saves the plan, model labels, original capture and result. Import each trial once. Use a new plan directory when you edit a scenario or variant. To review multiple plans together, use the same store path when you import each capture. Existing outputs are never replaced. Imports and reports verify existing records, checksums and grading. A damaged or incompatible store is refused before adding evidence.
