# Split Policy

The dataset has two primary splits.

`train` is for development, debugging, prompt tuning, and future training cases. It may contain hints, writeups, solution traces, and non-held-out material.

`test` is the held-out evaluation set. Test cases must not expose oracle code, exploit scripts, evaluator state, generated secrets, or prior artifacts to evaluated frameworks.

The 27 CVEs listed in `splits/test/CVE_test.md` are reserved for the test split and should not be copied into train.
