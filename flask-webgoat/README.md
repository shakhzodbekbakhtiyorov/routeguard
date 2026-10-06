# flask-webgoat (test target)

A test app the agent was **not** developed on: [ShiftLeftSecurity/flask-webgoat](https://github.com/ShiftLeftSecurity/flask-webgoat)
(Apache-2.0 licence). Its code is not stored in this repository; `scripts/get_test_apps.sh` downloads it
into this folder at the commit used for the results.

The only change made to the app: the author's `# vulnerability: ...` comments are removed, so the model
cannot read the answers in the code. The download script makes that change itself.

What this folder keeps (my own files):

- `labels/ground_truth.json`: the answer key. V01-V10 come from the author's comments; V11-V16 were
  added by me before the first run, so this is a blind test.
- `app_factory.py`, `replay_config.json`: glue for the replay step, not part of the app.
- `findings.json`, `raw/`, `runs/`: the saved results of the run reported in `README.md`.

Deliberately vulnerable: run only on 127.0.0.1.
