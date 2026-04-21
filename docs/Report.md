# Report

This file is a single global report for all processed CVEs.

## CVE-2026-32748

### Identity
- Product: squid
- Component: ICP v3 query handling when icp_port is enabled
- Severity: high
- Publication date: 2026-03-26
- CVSS: 7.5
- Attack type: denial-of-service

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-32748
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-32748
- Vendor advisory: https://github.com/squid-cache/squid/security/advisories/GHSA-f9p7-3jqg-hhvq, http://www.openwall.com/lists/oss-security/2026/03/25/3
- Upstream source or binary: https://github.com/squid-cache/squid/tree/SQUID_7_4, https://github.com/squid-cache/squid/tree/SQUID_7_5, https://github.com/squid-cache/squid/commit/703e07d25ca6fa11f52d20bf0bb879e22ab7481b
- Additional references: none

### Version selection
- Vulnerable version chosen: 7.4
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-32748
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: target starts reachable on TCP 3128, then crafted ICP v3 query traffic to UDP 3130 makes the vulnerable service unreachable on TCP 3128
- Negative-control expectation: none; this vuln-only lab has no fixed or verifier service, so no side-by-side comparison is performed

### Fidelity
- Level: faithful
- Rationale: the lab builds vulnerable Squid 7.4 and exercises the ICP v3 availability impact directly against that target
- Limitations: this is a vuln-only lab with no fixed-side comparison or verifier service; the lab validates service-availability impact from crafted ICP v3 traffic and does not model production cache workloads

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-32746

### Identity
- Product: GNU Inetutils telnetd
- Component: telnetd LINEMODE SLC suboption handling in add_slc
- Severity: critical
- Publication date: 2026-03-13
- CVSS: 9.8
- Attack type: buffer-overflow

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-32746
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-32746
- Vendor advisory: https://www.openwall.com/lists/oss-security/2026/03/12/4, http://www.openwall.com/lists/oss-security/2026/03/14/1, https://lists.gnu.org/archive/html/bug-inetutils/2026-03/msg00031.html
- Upstream source or binary: https://ftp.gnu.org/gnu/inetutils/inetutils-2.7.tar.gz, https://codeberg.org/inetutils/inetutils/src/tag/v2.7, https://codeberg.org/inetutils/inetutils/commit/6864598a29b652a6b69a958f5cd1318aa2b258af, https://codeberg.org/inetutils/inetutils/raw/commit/6864598a29b652a6b69a958f5cd1318aa2b258af/telnetd/slc.c
- Additional references: https://github.com/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746, https://codeberg.org/inetutils/inetutils/pulls/17

### Version selection
- Vulnerable version chosen: v2.7
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-32746
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: the solution connects to the vulnerable telnetd service, sends oversized LINEMODE SLC triplets, and observes an SLC response that the parity-check heuristic classifies as vulnerable
- Negative-control expectation: comparison not performed; this vuln-only lab contains only the vulnerable target

### Fidelity
- Level: faithful
- Rationale: source-built GNU Inetutils telnetd v2.7 is exercised over the network with the real LINEMODE SLC negotiation path; success is still limited to protocol-level vulnerable classification rather than a weaponized post-overflow payload
- Limitations: lab validates negotiation-stage exposure behavior through the observed SLC response classification and does not provide a weaponized post-overflow payload

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-32538

### Identity
- Product: SMTP Mailer
- Component: pre_wp_mail debug output path when smtp_mailer_send_test_email is user-controlled
- Severity: high
- Publication date: 2026-03-25
- CVSS: 7.5
- Attack type: sensitive-data-exposure

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-32538
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-32538
- Vendor advisory: https://patchstack.com/database/wordpress/plugin/smtp-mailer/vulnerability/wordpress-smtp-mailer-plugin-1-1-24-sensitive-data-exposure-vulnerability?_s_id=cve
- Upstream source or binary: https://downloads.wordpress.org/plugin/smtp-mailer.1.1.23.zip, https://downloads.wordpress.org/plugin/smtp-mailer.zip, https://plugins.svn.wordpress.org/smtp-mailer/tags/
- Additional references: https://plugins.svn.wordpress.org/smtp-mailer/tags/1.1.23/, https://plugins.svn.wordpress.org/smtp-mailer/trunk/

### Version selection
- Vulnerable version chosen: 1.1.23 (representative for <= 1.1.24 affected range)
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-32538
- Services used: target, solution, auxiliary, target-db
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: unauthenticated external POST to wp-login.php?action=lostpassword with smtp_mailer_send_test_email=1 causes the vulnerable target response to include the SMTP AUTH debug transcript for the configured credentials
- Negative-control expectation: comparison not performed; this vuln-only lab contains only the vulnerable target plus supporting target-db and auxiliary SMTP mock services

### Fidelity
- Level: partial
- Rationale: lab runs real WordPress with the real vulnerable SMTP Mailer plugin and demonstrates attacker-triggered SMTP debug-output leakage through the lost-password flow
- Limitations: affected range includes <= 1.1.24 but upstream artifact for 1.1.24 was not available in session; vulnerable control uses 1.1.23 from official plugin download archive; the downstream SMTP peer is an internal mock service that exists only to make the debug transcript deterministic

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-32524

### Identity
- Product: Photo Engine
- Component: legacy /?wplr-sync-api sync upload handler in classes/api.php (missing file-type validation)
- Severity: critical
- Publication date: 2026-03-25
- CVSS: 9.1
- Attack type: arbitrary-file-upload

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-32524
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-32524
- Vendor advisory: https://patchstack.com/database/wordpress/plugin/wplr-sync/vulnerability/wordpress-photo-engine-plugin-6-4-9-arbitrary-file-upload-vulnerability?_s_id=cve
- Upstream source or binary: https://downloads.wordpress.org/plugin/wplr-sync.6.4.9.zip, https://downloads.wordpress.org/plugin/wplr-sync.6.5.0.zip, https://plugins.svn.wordpress.org/wplr-sync/tags/6.4.9/, https://plugins.svn.wordpress.org/wplr-sync/tags/6.5.0/
- Additional references: https://plugins.svn.wordpress.org/wplr-sync/tags/

### Version selection
- Vulnerable version chosen: 6.4.9
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-32524
- Services used: target, solution, target-db
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated external POST multipart upload to /?wplr-sync-api with action=sync stores a PHP payload on the vulnerable target and the uploaded file executes with an attacker-controlled marker when fetched over HTTP
- Negative-control expectation: none; this vuln-only lab contains no fixed-side comparison

### Fidelity
- Level: faithful
- Rationale: lab runs real WordPress with the real vulnerable Photo Engine plugin and reproduces the authenticated legacy sync upload flow against the vulnerable target
- Limitations: the lab validates only the vulnerable target; no verifier, auxiliary service, or fixed-side control exists; uploaded PHP execution depends on the stock WordPress plus Apache PHP handling in this container and may differ on hardened deployments

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-32519

### Identity
- Product: Bit SMTP
- Component: REST API route middleware wiring for /wp-json/bit-smtp/v1/* in HookProvider::loadApi
- Severity: critical
- Publication date: 2026-03-25
- CVSS: 9.0
- Attack type: unauthenticated-config-tampering

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-32519
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-32519
- Vendor advisory: https://patchstack.com/database/wordpress/plugin/bit-smtp/vulnerability/wordpress-bit-smtp-plugin-1-2-2-broken-authentication-vulnerability?_s_id=cve
- Upstream source or binary: https://downloads.wordpress.org/plugin/bit-smtp.1.2.2.zip, https://downloads.wordpress.org/plugin/bit-smtp.1.2.3.zip, https://plugins.svn.wordpress.org/bit-smtp/tags/1.2.2/, https://plugins.svn.wordpress.org/bit-smtp/tags/1.2.3/
- Additional references: https://plugins.svn.wordpress.org/bit-smtp/tags/

### Version selection
- Vulnerable version chosen: 1.2.2
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-32519
- Services used: target, solution, target-db
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: unauthenticated external POST to /wp-json/bit-smtp/v1/mail/config/save modifies privileged SMTP configuration on vulnerable target and follow-up unauthenticated GET /mail/config/get exposes attacker-controlled marker in saved config
- Negative-control expectation: none; this vuln-only lab has no fixed-side comparison target

### Fidelity
- Level: faithful
- Rationale: lab runs real WordPress with the real Bit SMTP plugin version and demonstrates unauthenticated access to privileged REST configuration endpoints on the vulnerable release
- Limitations: lab validates endpoint-level broken authentication behavior and configuration tampering impact, not full post-compromise admin workflows; lab is vuln-only and does not include a verifier, auxiliary service, or fixed-side comparison target

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-32482

### Identity
- Product: Ona
- Component: admin-ajax child theme activation/update handlers in inc/admin/theme-admin.php (ona_activate_child_theme / ona_update_child_theme)
- Severity: critical
- Publication date: 2026-03-25
- CVSS: 9.9
- Attack type: remote-theme-install

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-32482
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-32482
- Vendor advisory: https://patchstack.com/database/wordpress/theme/ona/vulnerability/wordpress-ona-theme-1-24-arbitrary-file-upload-vulnerability?_s_id=cve
- Upstream source or binary: https://downloads.wordpress.org/theme/ona.1.23.2.zip, https://downloads.wordpress.org/theme/ona.1.24.zip, https://themes.svn.wordpress.org/ona/1.23.2/, https://themes.svn.wordpress.org/ona/1.24/
- Additional references: https://themes.svn.wordpress.org/ona/

### Version selection
- Vulnerable version chosen: 1.23.2
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-32482
- Services used: target, solution, target-db
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated low-privileged user can use a nonce-protected external POST to /wp-admin/admin-ajax.php with action=ona_activate_child_theme and an attacker-supplied download URL to trigger the vulnerable child-theme installation and activation workflow on the target (HTTP 200 with done=1)
- Negative-control expectation: none; this vuln-only lab has no fixed-side comparison target

### Fidelity
- Level: faithful
- Rationale: lab runs real WordPress with the real vulnerable Ona 1.23.2 theme and exercises the child-theme installation and activation AJAX flow from a low-privileged authenticated session in a vuln-only topology
- Limitations: the observed primitive is remote child-theme ZIP installation and activation through the handler's attacker-supplied download URL, not a general arbitrary local file upload primitive; the lab validates only the vulnerable target path and does not include a verifier or fixed-side control

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-29000

### Identity
- Product: pac4j-jwt
- Component: JwtAuthenticator encrypted-token validation path in org.pac4j.jwt.credentials.authenticator.JwtAuthenticator
- Severity: critical
- Publication date: 2026-03-04
- CVSS: 9.1
- Attack type: authentication-bypass

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-29000
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-29000
- Vendor advisory: https://www.pac4j.org/blog/security-advisory-pac4j-jwt-jwtauthenticator.html, https://www.vulncheck.com/advisories/pac4j-jwt-jwtauthenticator-authentication-bypass
- Upstream source or binary: https://repo1.maven.org/maven2/org/pac4j/pac4j-jwt/4.5.8/pac4j-jwt-4.5.8-sources.jar, https://repo1.maven.org/maven2/org/pac4j/pac4j-jwt/4.5.9/pac4j-jwt-4.5.9-sources.jar, https://repo1.maven.org/maven2/org/pac4j/pac4j-jwt/4.5.8/pac4j-jwt-4.5.8.jar, https://repo1.maven.org/maven2/org/pac4j/pac4j-jwt/4.5.9/pac4j-jwt-4.5.9.jar
- Additional references: https://www.codeant.ai/security-research/pac4j-jwt-authentication-bypass-public-key

### Version selection
- Vulnerable version chosen: 4.5.8
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-29000
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: attacker retrieves the public key from /jwks.json and submits an encrypted token carrying attacker-controlled unsigned claims to /whoami; the vulnerable target authenticates the forged admin identity and roles
- Negative-control expectation: none; this vuln-only lab contains no verifier, auxiliary service, or fixed-side comparison target

### Fidelity
- Level: faithful
- Rationale: lab compiles and runs pac4j-jwt 4.5.8 JwtAuthenticator logic inside a minimal Java HTTP harness and demonstrates the vulnerable authentication-bypass flow with an encrypted token carrying attacker-controlled unsigned claims
- Limitations: lab isolates the JwtAuthenticator validation boundary as a minimal Java HTTP harness and does not model a full production framework integration; current compose topology is vuln-only, so this lab does not include a fixed-side comparison service

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-27944

### Identity
- Product: nginx-ui
- Component: /api/backup unauthenticated backup export endpoint
- Severity: critical
- Publication date: 2026-03-05
- CVSS: 9.8
- Attack type: restricted-backup-read

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-27944
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-27944
- Vendor advisory: https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762
- Upstream source or binary: https://github.com/0xJacky/nginx-ui/releases/tag/v2.3.3, https://hub.docker.com/r/uozi/nginx-ui/tags?page=1&name=2.3.2, https://hub.docker.com/r/uozi/nginx-ui/tags?page=1&name=2.3.3
- Additional references: https://github.com/0xJacky/nginx-ui/tree/v2.3.2, https://github.com/0xJacky/nginx-ui/tree/v2.3.3

### Version selection
- Vulnerable version chosen: 2.3.2
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-27944
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: unauthenticated GET /api/backup on the vulnerable target returns HTTP 200 with a non-empty application backup archive and the endpoint's backup-related response headers
- Negative-control expectation: none; this vuln-only lab contains no fixed-side comparison target

### Fidelity
- Level: faithful
- Rationale: the lab uses the official vulnerable upstream nginx-ui image and exercises the real unauthenticated /api/backup behavior exposed by that version
- Limitations: the demonstrated primitive is retrieval of the service-defined backup archive contents exposed by /api/backup, not arbitrary reads from attacker-chosen filesystem paths; the repo currently validates only the vuln-only target path and does not include a fixed-side control for comparison

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-27880

### Identity
- Product: Grafana
- Component: OpenFeature OFREP evaluate flags API namespace validation body parsing in pkg/registry/apis/ofrep/register.go
- Severity: high
- Publication date: 2026-03-27
- CVSS: 7.5
- Attack type: denial-of-service

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-27880
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-27880
- Vendor advisory: https://grafana.com/security/security-advisories/cve-2026-27880
- Upstream source or binary: https://github.com/grafana/grafana/commit/0e5d9e01ef31f072fd41626cd744699374e70127, https://github.com/grafana/grafana/commit/576f2e81b33bc857df779c95cb38effaa6c58b03, https://raw.githubusercontent.com/grafana/grafana/v12.2.7/pkg/registry/apis/ofrep/register.go, https://raw.githubusercontent.com/grafana/grafana/v12.2.8/pkg/registry/apis/ofrep/register.go
- Additional references: https://cveawg.mitre.org/api/cve/CVE-2026-27880

### Version selection
- Vulnerable version chosen: 12.2.7
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-27880
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: unauthenticated external POST to OFREP evaluate flags endpoint with a body larger than 1 MiB is fully read and processed by vulnerable target (HTTP 200)
- Negative-control expectation: comparison not performed; this vuln-only lab contains only the vulnerable target and solution containers

### Fidelity
- Level: faithful
- Rationale: lab reproduces the vulnerable oversized-request acceptance behavior in the OFREP evaluate-flags path
- Limitations: lab isolates OFREP handler behavior and does not run full Grafana service stack; denial-of-service impact is validated as oversized-request acceptance vs rejection, not as host-level OOM crash induction

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-27855

### Identity
- Product: OX Dovecot Pro
- Component: OTP authentication cache handling when username is altered in passdb
- Severity: medium
- Publication date: 2026-03-27
- CVSS: 6.8
- Attack type: replay-attack

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-27855
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-27855
- Vendor advisory: https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2026/oxdc-adv-2026-0001.json
- Upstream source or binary: https://raw.githubusercontent.com/dovecot/core/2.3.20/src/auth/auth-cache.c, https://raw.githubusercontent.com/dovecot/core/2.3.20/src/auth/passdb-cache.c, https://raw.githubusercontent.com/dovecot/core/2.3.20/src/auth/mech-otp.c, https://raw.githubusercontent.com/dovecot/core/2.3.20/src/auth/auth-request.c, https://raw.githubusercontent.com/dovecot/core/2.4.3/src/auth/auth-cache.c
- Additional references: https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2026/oxdc-adv-2026-0001.json

### Version selection
- Vulnerable version chosen: <=2.3.0
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/medium/CVE-2026-27855
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: after one legitimate OTP authentication, replay of the captured OTP response is accepted because the stale translated-user cache entry survives the credential update
- Negative-control expectation: comparison not performed; no fixed control is present in the compose topology

### Fidelity
- Level: partial
- Rationale: lab models the vulnerable OTP cache-removal logic with a deterministic replay sequence against the vulnerable target only
- Limitations: does not run full Dovecot daemon or real OTP wire protocol handshake; validates cache-removal replay condition with faithful logic model rather than live upstream binary execution; validates the vulnerable target only; no fixed-side comparison service exists in this lab

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-27734

### Identity
- Product: beszel
- Component: hub container info/logs passthrough to agent Docker API path construction
- Severity: high
- Publication date: 2026-02-27
- CVSS: 6.5
- Attack type: path-traversal

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-27734
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-27734
- Vendor advisory: https://github.com/henrygd/beszel/security/advisories/GHSA-phwh-4f42-gwf3
- Upstream source or binary: https://github.com/henrygd/beszel/releases/tag/v0.18.4, https://raw.githubusercontent.com/henrygd/beszel/v0.18.3/agent/docker.go, https://raw.githubusercontent.com/henrygd/beszel/v0.18.4/agent/docker.go
- Additional references: none

### Version selection
- Vulnerable version chosen: < 0.18.4
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-27734
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated readonly user supplies a traversal container parameter to /api/beszel/containers/info and the vulnerable target returns data from a non-container simulated Docker API endpoint such as /version
- Negative-control expectation: same-target baseline only; exploit success is evaluated on the vulnerable target without a comparison service

### Fidelity
- Level: partial
- Rationale: lab models the vulnerable container parameter interpolation path and demonstrates traversal from the Beszel-like handler into a simulated Docker API endpoint map
- Limitations: target is a minimal Beszel-like HTTP handler rather than a full Beszel deployment; backend exposure is limited to a small in-memory set of simulated Docker API endpoints rather than arbitrary Docker daemon or filesystem access

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-26352

### Identity
- Product: Express
- Component: /cgi-bin/vpnmain.cgi VPN_IP parameter handling in VPN configuration UI
- Severity: medium
- Publication date: 2026-03-30
- CVSS: 5.4
- Attack type: cross-site-scripting

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-26352
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-26352
- Vendor advisory: https://community.smoothwall.org/forum/viewtopic.php?t=45095, https://www.vulncheck.com/advisories/smoothwall-express-stored-xss-in-vpnmain-cgi-via-vpn-ip-parameter
- Upstream source or binary: https://sourceforge.net/projects/smoothwall/
- Additional references: https://community.smoothwall.org/forum/viewtopic.php?t=45095, https://www.vulncheck.com/advisories/smoothwall-express-stored-xss-in-vpnmain-cgi-via-vpn-ip-parameter

### Version selection
- Vulnerable version chosen: < 3.1 Update 13
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/medium/CVE-2026-26352
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated attacker stores a VPN_IP value containing script markup and a later vpnmain.cgi page view renders the raw script string without escaping in the vulnerable target
- Negative-control expectation: comparison not performed; no fixed control is present in the compose topology

### Fidelity
- Level: partial
- Rationale: lab models the authenticated stored XSS workflow in vpnmain.cgi with a deterministic HTTP harness that preserves the vulnerable unsanitized reflection behavior
- Limitations: does not boot full Smoothwall Express appliance image; models only the vulnerable target path; no verifier, auxiliary service, or fixed control is included

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-26073

### Identity
- Product: EVerest
- Component: modules/EVSE/OCPP shared event_queue writes in subscribe_powermeter_public_key_ocmf callback while OCPP is not started
- Severity: medium
- Publication date: 2026-03-26
- CVSS: 5.9
- Attack type: race-condition

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-26073
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-26073
- Vendor advisory: https://github.com/EVerest/EVerest/security/advisories/GHSA-jf36-f4f9-7qc2
- Upstream source or binary: https://raw.githubusercontent.com/EVerest/EVerest/2025.12.1/modules/EVSE/OCPP/OCPP.cpp, https://raw.githubusercontent.com/EVerest/EVerest/2026.02.0/modules/EVSE/OCPP/OCPP.cpp, https://raw.githubusercontent.com/EVerest/EVerest/2025.12.1/modules/EVSE/OCPP/OCPP.hpp, https://raw.githubusercontent.com/EVerest/EVerest/2026.02.0/modules/EVSE/OCPP/OCPP.hpp
- Additional references: none

### Version selection
- Vulnerable version chosen: < 2026.02.0
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/medium/CVE-2026-26073
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: external scenario trigger causes concurrent session and powermeter public key callbacks while OCPP is not started and vulnerable target reports race_detected=true with simulated queue corruption
- Negative-control expectation: comparison not performed; this vuln-only lab has no fixed control

### Fidelity
- Level: partial
- Rationale: lab models the advisory-described event_queue race where the vulnerable powermeter public key callback writes without acquiring event_mutex
- Limitations: does not compile or run the full EVerest EVSE OCPP runtime stack; models queue corruption as a deterministic signal instead of reproducing TSAN or ASAN runtime diagnostics; validates the vulnerable target only; no fixed-side comparison service exists in this lab

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-25887

### Identity
- Product: chartbrew
- Component: server/controllers/ChartController.js runQuery/testMongoQuery Function-based MongoDB query execution
- Severity: high
- Publication date: 2026-03-06
- CVSS: 7.2
- Attack type: remote-code-execution

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-25887
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-25887
- Vendor advisory: https://github.com/chartbrew/chartbrew/security/advisories/GHSA-x4r6-prmw-7wvw
- Upstream source or binary: https://github.com/chartbrew/chartbrew/releases/tag/v4.8.1, https://github.com/chartbrew/chartbrew/commit/12ef4ff1d5b9192fc1371cc812b6a6e2f1f96aa9, https://raw.githubusercontent.com/chartbrew/chartbrew/403a24180ee96cda9665d30cd6a9a2952bee3d31/server/controllers/ChartController.js, https://raw.githubusercontent.com/chartbrew/chartbrew/12ef4ff1d5b9192fc1371cc812b6a6e2f1f96aa9/server/controllers/ChartController.js, https://raw.githubusercontent.com/chartbrew/chartbrew/12ef4ff1d5b9192fc1371cc812b6a6e2f1f96aa9/server/modules/validateMongoQuery.js
- Additional references: none

### Version selection
- Vulnerable version chosen: < 4.8.1
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-25887
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated attacker submits crafted MongoDB query string through query-test endpoint and vulnerable target executes constructor-chain payload, setting rce marker
- Negative-control expectation: none; exploit success is validated against the vulnerable target only

### Fidelity
- Level: partial
- Rationale: lab reproduces the vulnerable Function-based MongoDB query execution path that enables constructor-chain code execution
- Limitations: does not run full Chartbrew application stack, database, and UI workflows; focuses on server-side query-evaluation boundary rather than full chart rendering pipeline

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-25361

### Identity
- Product: WpEvently
- Component: wp-admin/admin.php page=mep_event search parameter reflected output path
- Severity: high
- Publication date: 2026-03-25
- CVSS: 7.1
- Attack type: cross-site-scripting

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-25361
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-25361
- Vendor advisory: https://patchstack.com/database/Wordpress/Plugin/mage-eventpress/vulnerability/wordpress-wpevently-plugin-5-1-4-reflected-cross-site-scripting-xss-vulnerability?_s_id=cve
- Upstream source or binary: https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=mage-eventpress, https://plugins.svn.wordpress.org/mage-eventpress/tags/, https://plugins.svn.wordpress.org/mage-eventpress/trunk/readme.txt, https://plugins.svn.wordpress.org/mage-eventpress/trunk/inc/MPWEM_Shortcodes.php, https://plugins.svn.wordpress.org/mage-eventpress/trunk/admin/MPWEM_Event_Lists.php, https://plugins.svn.wordpress.org/mage-eventpress/trunk/inc/MPWEM_Query.php
- Additional references: https://cveawg.mitre.org/api/cve/CVE-2026-25361

### Version selection
- Vulnerable version chosen: <= 5.1.4
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-25361
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: external attacker submits script payload to reflected admin search parameter and vulnerable target response contains raw script tag in rendered HTML
- Negative-control expectation: no fixed control is present in this vuln-only lab; comparison is not performed

### Fidelity
- Level: partial
- Rationale: lab models the reported WpEvently admin search endpoint shape with a minimal HTTP service that reflects attacker-controlled input into the rendered HTML response without escaping
- Limitations: lab is a deterministic reproduction harness and does not boot full WordPress plus plugin runtime; lab demonstrates vulnerable reflection only; no fixed-side comparison service is included

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-25116

### Identity
- Product: runtipi
- Component: unauthenticated UserConfigController PUT /api/user-config/:urn with insecure URN parsing to AppFilesManager path join for docker-compose.yml overwrite
- Severity: high
- Publication date: 2026-01-29
- CVSS: 7.6
- Attack type: path-traversal

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-25116
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-25116
- Vendor advisory: https://github.com/runtipi/runtipi/security/advisories/GHSA-mwg8-x997-cqw6
- Upstream source or binary: https://github.com/runtipi/runtipi/releases/tag/v4.7.2, https://raw.githubusercontent.com/runtipi/runtipi/v4.7.1/packages/backend/src/modules/user-config/user-config.controller.ts, https://raw.githubusercontent.com/runtipi/runtipi/v4.7.2/packages/backend/src/modules/user-config/user-config.controller.ts, https://raw.githubusercontent.com/runtipi/runtipi/v4.7.1/packages/backend/src/common/helpers/app-helpers.ts, https://raw.githubusercontent.com/runtipi/runtipi/v4.7.2/packages/backend/src/common/helpers/app-helpers.ts, https://raw.githubusercontent.com/runtipi/runtipi/v4.7.1/packages/backend/src/modules/apps/app-files-manager.ts, https://raw.githubusercontent.com/runtipi/runtipi/v4.7.2/packages/backend/src/modules/apps/app-files-manager.ts
- Additional references: none

### Version selection
- Vulnerable version chosen: >= 4.5.0, < 4.7.2
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-25116
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: unauthenticated external PUT to /api/user-config/.:.. writes the attacker-supplied docker compose payload into /data/docker-compose.yml on the vulnerable target
- Negative-control expectation: no fixed control is present in this vuln-only lab; comparison is not performed

### Fidelity
- Level: partial
- Rationale: lab models the vulnerable URN path handling with a minimal service that allows .:.. traversal to overwrite the target's /data/docker-compose.yml
- Limitations: does not boot the full runtipi NestJS stack or restart overwritten services; demonstrates a compose overwrite outcome only; no fixed-side comparison service is included

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-24512

### Identity
- Product: ingress-nginx
- Component: rules.http.paths.path ingress field rendered into nginx location block allowing configuration injection
- Severity: high
- Publication date: 2026-02-03
- CVSS: 8.8
- Attack type: configuration-injection

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-24512
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-24512
- Vendor advisory: https://github.com/kubernetes/kubernetes/issues/136678
- Upstream source or binary: https://github.com/kubernetes/ingress-nginx, https://kubernetes.github.io/ingress-nginx/deploy/upgrade/
- Additional references: https://api.github.com/repos/kubernetes/kubernetes/issues/136678, https://cveawg.mitre.org/api/cve/CVE-2026-24512

### Version selection
- Vulnerable version chosen: < v1.13.7 and < v1.14.3
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-24512
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: a benign ingress apply leaves injection and secret-exposure signals false, then an attacker-controlled ImplementationSpecific path with newline-delimited nginx directives is accepted and rendered into generated nginx configuration with the modeled secret-exposure signal
- Negative-control expectation: same-target baseline only; no fixed-side comparison is performed in this vuln-only lab

### Fidelity
- Level: partial
- Rationale: lab models externally triggered ingress path injection into nginx configuration generation and captures post-render config injection and secret disclosure signal in controller context
- Limitations: does not run a full Kubernetes cluster with ingress-nginx controller deployment

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-24061

### Identity
- Product: Inetutils
- Component: telnetd authentication header parsing and login validation path
- Severity: critical
- Publication date: 2026-01-21
- CVSS: 9.8
- Attack type: authentication-bypass

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-24061
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-24061
- Vendor advisory: https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html, https://www.vicarius.io/vsociety/posts/cve-2026-24061-mitigation-script-remote-authentication-bypass-in-gnu-inetutils-package
- Upstream source or binary: https://codeberg.org/inetutils/inetutils/commit/fd702c02497b2f398e739e3119bed0b23dd7aa7b, https://codeberg.org/inetutils/inetutils/commit/ccba9f748aa8d50a38d7748e2e60362edd6a32cc
- Additional references: https://www.openwall.com/lists/oss-security/2026/01/20/2, https://www.openwall.com/lists/oss-security/2026/01/20/8, https://www.gnu.org/software/inetutils/, https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html, https://www.vicarius.io/vsociety/posts/cve-2026-24061-detection-script-remote-authentication-bypass-in-gnu-inetutils-package, https://www.vicarius.io/vsociety/posts/cve-2026-24061-mitigation-script-remote-authentication-bypass-in-gnu-inetutils-package, http://www.openwall.com/lists/oss-security/2026/01/22/1, https://lists.debian.org/debian-lts-announce/2026/01/msg00025.html, https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-24061, https://www.labs.greynoise.io/grimoire/2026-01-22-f-around-and-find-out-18-hours-of-unsolicited-houseguests/index.html, https://www.openwall.com/lists/oss-security/2026/01/20/2#:~:text=root@...a%3A~%20USER='

### Version selection
- Vulnerable version chosen: 1.9.3
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-24061
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: attacker sends crafted auth_header payload to /api/telnet/login; vulnerable target authenticates and /status reports login_bypassed=true
- Negative-control expectation: none; this vuln-only lab does not provide a fixed-side comparison target

### Fidelity
- Level: partial
- Rationale: deterministic harness models the externally triggered authentication-bypass boundary and vulnerable header parsing behavior in a minimal service
- Limitations: does not compile or run full inetutils telnetd binaries and daemon process model; models parser and authentication boundary behavior in a minimal HTTP test harness

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-23837

### Identity
- Product: MyTube
- Component: backend authentication middleware protecting /api/settings
- Severity: critical
- Publication date: 2026-01-19
- CVSS: 9.8
- Attack type: authentication-bypass

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-23837
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-23837
- Vendor advisory: https://github.com/franklioxygen/MyTube/security/advisories/GHSA-cmvj-g69f-8664
- Upstream source or binary: https://github.com/franklioxygen/MyTube/commit/f85ae9b0d6e4a6480c6af5b675a99069d08d496e, https://github.com/franklioxygen/MyTube/releases/tag/v1.7.65, https://github.com/franklioxygen/MyTube/releases/tag/v1.7.66
- Additional references: https://github.com/franklioxygen/MyTube/security/advisories/GHSA-cmvj-g69f-8664, https://github.com/franklioxygen/MyTube/tree/v1.7.65, https://github.com/franklioxygen/MyTube/tree/v1.7.66

### Version selection
- Vulnerable version chosen: 1.7.65
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-23837
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: with loginEnabled=true and no auth cookie, attacker GET /api/settings against the vulnerable target returns HTTP 200 and exposes the settings payload
- Negative-control expectation: none; this vuln-only lab contains no fixed-side comparison

### Fidelity
- Level: faithful
- Rationale: the target builds the vulnerable MyTube release and seeds loginEnabled=true so the unauthenticated /api/settings exposure is reproducible in a vuln-only topology
- Limitations: the lab validates only the vulnerable target; no verifier, auxiliary, or fixed-side control exists; the entrypoint seeds backend settings for deterministic login-required state before the service starts

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-22804

### Identity
- Product: Termix
- Component: src/ui/desktop/apps/file-manager/components/FileViewer.tsx SVG preview rendering path
- Severity: high
- Publication date: 2026-01-12
- CVSS: 8.0
- Attack type: cross-site-scripting

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-22804
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-22804
- Vendor advisory: https://github.com/Termix-SSH/Termix/security/advisories/GHSA-m3cv-5hgp-hv35
- Upstream source or binary: not found in-session
- Additional references: https://github.com/Termix-SSH/Termix/security/advisories/GHSA-m3cv-5hgp-hv35

### Version selection
- Vulnerable version chosen: >= 1.7.0, < 1.10.0
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-22804
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated same-target baseline preview of a benign svg leaves both XSS signals false, then malicious svg upload and preview returns unsanitized attacker-controlled onerror content with stored_xss_triggered=true and client_script_execution_possible=true
- Negative-control expectation: same-target baseline only; benign preview should leave stored_xss_triggered=false and client_script_execution_possible=false before exploit upload, and no fixed-side comparison is performed

### Fidelity
- Level: partial
- Rationale: lab models an authenticated stored-SVG-XSS preview path with deterministic same-target baseline and exploit signals
- Limitations: does not run the full Termix frontend, backend, and Electron stack; client-side script execution is represented by deterministic preview and status booleans rather than a real browser runtime

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-22265

### Identity
- Product: roxy-wi
- Component: app/modules/roxywi/logs.py show_roxy_log grep parameter command construction
- Severity: high
- Publication date: 2026-01-15
- CVSS: 7.5
- Attack type: os-command-injection

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-22265
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-22265
- Vendor advisory: https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-mmmf-vh7m-rm47
- Upstream source or binary: https://github.com/roxy-wi/roxy-wi/commit/f040d3338c4ba6f66127487361592e32e0188eee, https://github.com/roxy-wi/roxy-wi/releases/tag/v8.2.8.2
- Additional references: none

### Version selection
- Vulnerable version chosen: < 8.2.8.2
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-22265
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: authenticated attacker submits logs view request with grep payload containing newline and vulnerable target command construction executes injected command path with command_injection=true and root-context marker in output
- Negative-control expectation: same-target metacharacter filtering exists for some characters, but this lab does not include a fixed-side or verifier comparison

### Fidelity
- Level: partial
- Rationale: lab models the authenticated log-view flow and reproduces the advisory-described newline command-injection boundary in vulnerable command construction,
- Limitations: does not boot full roxy-wi stack with SSH backend and real syslog files; models command construction and sanitizer behavior in deterministic harness

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-21858

### Identity
- Product: n8n
- Component: form-based workflow webhook request parsing and file handling boundary (parseRequestBody, parseFormData/parseBody, prepareFormReturnItem, copyBinaryFile)
- Severity: critical
- Publication date: 2026-01-07
- CVSS: 10.0
- Attack type: restricted-file-read

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-21858
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-21858
- Vendor advisory: https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg
- Upstream source or binary: https://github.com/n8n-io/n8n, https://www.npmjs.com/package/n8n/v/1.121.0
- Additional references: https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858

### Version selection
- Vulnerable version chosen: >= 1.65.0, < 1.121.0
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-21858
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: unauthenticated attacker sends application/json payload overriding files.upload.filepath to /etc/passwd and the vulnerable target returns preview content from its hardcoded simulated system-file mapping
- Negative-control expectation: none; this vuln-only lab contains no fixed-side comparison

### Fidelity
- Level: partial
- Rationale: lab models advisory-described content-type confusion in the form webhook flow with a minimal Python harness where a JSON body can override req.body.files and drive file preview selection through a simulated path mapping
- Limitations: does not run full n8n runtime, database, or execute-command node chain; target serves previews only for hardcoded upload and simulated system-file paths, so the primitive is restricted and not an arbitrary container filesystem read; runtime artifacts may preserve raw target field names such as unauthorized_file_access, but those names refer only to the simulated mapping behavior in this harness

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-4907

### Identity
- Product: Page Replica
- Component: synthetic SSRF-boundary model
- Severity: medium
- Publication date: 2026-03-27
- CVSS: 6.3
- Attack type: server-side-request-forgery

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-4907
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-4907
- Vendor advisory: https://vuldb.com/?submit.777447
- Upstream source or binary: https://github.com/lakshayyverma/CVE-Discovery/blob/main/page_replica.md
- Additional references: https://vuldb.com/?id.353658, https://vuldb.com/?ctiid.353658, https://github.com/lakshayyverma/CVE-Discovery/blob/main/page_replica.md, https://vuldb.com/?submit.777447

### Version selection
- Vulnerable version chosen: e4a7f52e75093ee318b4d5a9a9db6751050d2ad0
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/medium/CVE-2026-4907
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: starting from /status success=false, a POST to /trigger with the lab token makes the vulnerable target report success=true
- Negative-control expectation: comparison not performed; no fixed control, verifier, or auxiliary service exists in the compose topology

### Fidelity
- Level: synthetic
- Rationale: deterministic harness models only the vulnerable SSRF trigger boundary on the target and validates the vulnerable state transition without a fixed-side comparison service
- Limitations: does not compile or run the full upstream product stack; does not perform a real outbound SSRF fetch; attack path models the vulnerable trigger boundary and validation workflow only

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-1642

### Identity
- Product: NGINX Open Source
- Component: upstream TLS proxy response handling boundary with potential MITM plaintext injection prefix acceptance
- Severity: high
- Publication date: 2026-02-04
- CVSS: 5.9
- Attack type: data-injection

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-1642
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-1642
- Vendor advisory: https://my.f5.com/manage/s/article/K000159824
- Upstream source or binary: https://github.com/nginx/nginx/releases/tag/release-1.28.2, https://github.com/nginx/nginx/releases/tag/release-1.29.5, https://github.com/nginx/nginx/pull/1114/changes/376c3739b633e4ddac8ecf59d72e43b0b9151c51
- Additional references: http://www.openwall.com/lists/oss-security/2026/02/05/1

### Version selection
- Vulnerable version chosen: 1.3.0
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-1642
- Services used: target, solution, auxiliary
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: attacker sets a plaintext prefix on the simulated upstream and an external request to the vulnerable /api/proxy/fetch endpoint returns a body containing that prefix while target status reports injection_detected=true
- Negative-control expectation: same-target baseline only; the lab verifies that injection_detected is false before the attack request, and no fixed-side comparison is performed

### Fidelity
- Level: partial
- Rationale: lab models an externally triggered upstream-response fetch flow where a vulnerable proxy accepts an attacker-controlled plaintext prefix from a simulated upstream response
- Limitations: does not build nginx binaries or run real TLS handshake against upstream service; models response authenticity boundary and prefix filtering semantics in deterministic HTTP harness

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-1580

### Identity
- Product: ingress-nginx
- Component: nginx.ingress.kubernetes.io/auth-method annotation rendered into nginx auth_request_method directive allowing config injection
- Severity: high
- Publication date: 2026-02-03
- CVSS: 8.8
- Attack type: configuration-injection

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-1580
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-1580
- Vendor advisory: https://github.com/kubernetes/kubernetes/issues/136677
- Upstream source or binary: https://github.com/kubernetes/ingress-nginx, https://kubernetes.github.io/ingress-nginx/deploy/upgrade/, https://github.com/kubernetes/kubernetes/issues/136677
- Additional references: https://api.github.com/repos/kubernetes/kubernetes/issues/136677, https://cveawg.mitre.org/api/cve/CVE-2026-1580, https://github.com/kubernetes/kubernetes/issues/136677

### Version selection
- Vulnerable version chosen: < v1.13.7 and < v1.14.3
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/high/CVE-2026-1580
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: attacker submits an ingress whose auth-method annotation contains embedded newlines and the vulnerable target renders the injected directive into the generated nginx config while flipping the simulated secret exposure signal
- Negative-control expectation: same-target baseline only; a normal auth-method value should not trigger injection before the attack request, and no fixed-side comparison is performed

### Fidelity
- Level: partial
- Rationale: lab models externally triggered newline-based auth-method annotation injection during nginx configuration generation and validates the injected directive plus simulated secret exposure signal on the vulnerable target
- Limitations: does not run a full Kubernetes cluster with ingress-nginx controller deployment; models controller config-render and validation boundary in a deterministic harness

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-1561

### Identity
- Product: WebSphere Application Server Liberty
- Component: samlWeb-2.0 enabled URL fetch path allowing outbound request to attacker-chosen target
- Severity: medium
- Publication date: 2026-03-25
- CVSS: 5.4
- Attack type: server-side-request-forgery

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-1561
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-1561
- Vendor advisory: https://www.ibm.com/support/pages/node/7267347
- Upstream source or binary: https://openliberty.io/docs/latest/reference/feature/samlWeb-2.0.html, https://www.ibm.com/support/pages/node/7267347
- Additional references: none

### Version selection
- Vulnerable version chosen: 17.0.0.3
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/medium/CVE-2026-1561
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: attacker submits the lab's simulated internal metadata URL and the vulnerable target returns mapped internal metadata content
- Negative-control expectation: comparison not performed; this vuln-only lab has no fixed control

### Fidelity
- Level: partial
- Rationale: lab models a deterministic SSRF-style URL fetch path and exposes simulated internal metadata through a hardcoded internal mapping
- Limitations: does not run full Liberty runtime and real samlWeb-2.0 feature implementation; does not perform real outbound network fetches; internal metadata responses come from a built-in mapping; validates the vulnerable target only; no fixed-side comparison service exists in this lab

### Validation
- Completeness: vuln-only
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: intentionally omitted by vuln-only lab policy
- Fixed result: not evaluated (vulnerable path only)
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

## CVE-2026-1324

### Identity
- Product: Operation and Maintenance Management System
- Component: SessionController-style /isomp-protocol/protocol/session keypassword handling in the SSH Protocol Handler, modeled as a partial behavioral reproduction
- Severity: critical
- Publication date: 2026-01-22
- CVSS: 8.8
- Attack type: os-command-injection

### Sources
- CVE.org: https://www.cve.org/CVERecord?id=CVE-2026-1324
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-1324
- Vendor advisory: https://vuldb.com/?submit.735716
- Upstream source or binary: https://github.com/LX-LX88/cve/issues/20
- Additional references: https://vuldb.com/?id.342300, https://vuldb.com/?ctiid.342300

### Version selection
- Vulnerable version chosen: <= 3.0.12
- Evidence: CVE/NVD description and listed affected range
- Fixed version chosen: unavailable
- Evidence: vendor/upstream advisory references
- Ambiguities: see limitations

### Lab design
- Severity directory: src/critical/CVE-2026-1324
- Services used: target, solution
- Exposed ports: target 127.0.0.1:9090
- Network boundaries: host only to target, internal compose network for all service-to-service calls
- External trigger path: solution container executes explicit attacker request after startup
- Success condition: attacker submits POST /isomp-protocol/protocol/session with a malicious keypassword and the vulnerable target creates /tmp/lab-runtime/markers/rce-marker.txt with the expected token
- Negative-control expectation: a benign request to the same endpoint reaches the helper without creating the marker file

### Fidelity
- Level: partial
- Rationale: lab models the reported SSH session keypassword flow where attacker-controlled input reaches a real shell command and produces a bounded marker-file side effect
- Limitations: does not run real Sangfor product code; narrows the vulnerability to the reported keypassword-to-command boundary rather than reproducing the full management stack and SSH backend

### Validation
- Completeness: complete
- Vulnerable build: scaffold prepared; full upstream reproduction pending
- Vulnerable result: deterministic attacker path defined in solution container
- Fixed build: not feasible in-session
- Fixed result: a benign request to the same endpoint reaches the helper without creating the marker file
- Blocker if incomplete: none
- Notes: processed in order from CVE_list.txt

