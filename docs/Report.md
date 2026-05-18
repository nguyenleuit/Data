# Report

Current benchmark state:

- Train split: 40 runnable development/training cases listed in `splits/train/CVE_train.md`.
- Test split: 27 CVE cases listed in `splits/test/CVE_test.md`.
- Runnable test labs: 27/27 have compose targets, public tasks, hidden oracles, and smoke artifacts.
- Fidelity distribution: 8 `faithful`, 15 `near-faithful`, 4 `cve-specific-emulated`.
- Fixed negative controls: 27 present, 0 deferred.
- Framework adapters: public-only exporters for HackSynth, PentestGPT, PentestAgent, and VulnBot; `manual` is the baseline no-op runner.

The faithful cases are:

- `CVE-2026-1642`: NGINX Open Source 1.28.0 proxy TLS verification runtime with a lab-local mismatched-cert HTTPS upstream and fixed verification control.
- `CVE-2026-23837`: MyTube v1.7.65 role-based middleware runtime with patched v1.7.66 middleware fixed-control rejection.
- `CVE-2026-27944`: nginx-ui 2.3.2 unauthenticated backup runtime with upstream 2.3.3 fixed-control rejection.
- `CVE-2026-29000`: pac4j-jwt 4.5.8 JwtAuthenticator encrypted JWT runtime with upstream 4.5.9 fixed-control rejection.
- `CVE-2026-32524`: WordPress with real Photo Engine wplr-sync 6.4.9 accepting a dangerous-extension upload and real 6.5.0 fixed-control MIME rejection.
- `CVE-2026-32538`: WordPress with real SMTP Mailer 1.1.23 exposing lab-only SMTP credentials through debug output and current fixed-control redaction.
- `CVE-2026-32748`: Squid SQUID_7_4 UDP ICP runtime with upstream Squid 7.5 malformed ICP fixed-control rejection.
- `CVE-2026-24061`: GNU Inetutils 2.7 telnetd USER environment login invocation runtime with a lab-local safe login helper and fixed rejection control.

The upgraded near-faithful cases are:

- `CVE-2026-32746`: GNU Inetutils telnetd LINEMODE/SLC fixture with fixed SLC control.
- `CVE-2026-21858`: n8n form webhook file-access fixture with fixed traversal rejection control.
- `CVE-2026-1580`: ingress-nginx auth-method annotation renderer fixture with fixed annotation rejection control.
- `CVE-2026-22265`: roxy-wi logs.py grep parameter fixture with fixed command-injection rejection control.
- `CVE-2026-24512`: ingress-nginx path renderer fixture with fixed path-injection rejection control.
- `CVE-2026-25116`: Runtipi UserConfigController fixture with fixed traversal/config-overwrite rejection control.
- `CVE-2026-25887`: Chartbrew runMongo query fixture with fixed code-injection rejection control.
- `CVE-2026-27880`: Grafana OpenFeature evaluation endpoint fixture with fixed oversized-input rejection control.
- `CVE-2026-32482`: Ona theme upload-handler fixture backed by pinned WordPress theme ZIP with fixed upload rejection control.
- `CVE-2026-32519`: Bit SMTP settings/privilege fixture backed by pinned WordPress plugin ZIP with fixed authorization control.
- `CVE-2026-22804`: Termix FileViewer SVG preview fixture backed by pinned source release with fixed sanitization control.
- `CVE-2026-25361`: WpEvently reflected-rendering fixture backed by pinned WordPress plugin ZIP with fixed escaping control.
- `CVE-2026-27734`: Beszel container info/logs fixture backed by pinned source release with fixed path validation control.
- `CVE-2026-26073`: EVerest OCPP powermeter queue fixture backed by pinned upstream source file with fixed queue validation control.
- `CVE-2026-27855`: Dovecot auth-cache OTP replay fixture backed by pinned upstream source file with fixed replay rejection control.

Known limitations:

- Eight test cases currently run real upstream product, service, or library runtimes; the remaining upgraded cases are near-faithful fixtures with pinned upstream/advisory references.
- The remaining 4 test cases are CVE-specific emulations with deterministic local impact markers and fixed negative controls because exact upstream artifacts or full runtime setup remain unavailable.
- Framework-specific execution is not wired beyond public task export and the manual no-op adapter.
- Hidden oracles remain per-case scripts; the common evaluator provides the runner API surface but not full case-specific grading logic.

Train split summary:

- 40/40 train cases have compose targets, public tasks, hidden oracles, solution material, and validation artifacts.
- Fidelity distribution: 4 `faithful`, 17 `near-faithful`, 19 `cve-specific-emulated`.
- Fixed negative controls are not required for train cases under the current split policy.
