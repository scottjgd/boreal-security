=== Boreal Security ===
Contributors: borealformstudio
Tags: security, malware scan, audit log, login security, integrity
Requires at least: 5.8
Tested up to: 6.8
Stable tag: 1.0.1
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Evidence-first, resumable security scans, privacy-conscious login throttling, audit history, and portable reports.

== Description ==

Boreal Security performs explicit, bounded scans and records the evidence behind every finding. Free remains useful indefinitely and has no licence check, telemetry, vendor updater, or background vendor request.

Free includes WordPress/PHP/update posture, configuration checks, official WordPress core checksums, permissions and exposed-file checks, administrator posture, bounded uploads heuristics, database persistence indicators, audit history, JSON/CSV exports, Site Health, WP-CLI, and hashed-IP brute-force throttling with trusted-IP recovery.

Plugin and theme inventory is clearly marked unverifiable when no trusted checksum source is available. Heuristics can produce false positives and never silently claim a failed check passed.

An optional separately installed Pro add-on adds scheduled scans, file baselines, email alerts, confirmed quarantine with backup, and agency reports. Free scanning and protection are never licence-gated.

== External services ==

Only when an administrator explicitly starts a scan, Boreal Security requests official core checksums from the WordPress.org Core API. The request includes the installed WordPress version and locale. WordPress.org terms: https://wordpress.org/about/ and privacy policy: https://wordpress.org/about/privacy/

No vulnerability feed is bundled. Site owners may connect a lawfully licensed provider through the documented WordPress filter architecture.

== Installation ==

1. Install and activate Boreal Security.
2. Open Boreal Security and choose Run manual scan.
3. Review evidence and remediation under Findings.
4. Configure login throttling and trusted recovery IPs under Settings.

== Frequently Asked Questions ==

= Does Free require a licence? =

No. Scanning, reports, integrations, throttling, and audit history remain available without Pro.

= Does a missing checksum mean a file is safe? =

No. An unavailable official checksum request is an explicit error finding. Plugin/theme integrity is marked unverifiable when trusted checksums are unavailable.

== WP-CLI ==

Run `wp boreal-security` to execute bounded batches until the scan completes or fails explicitly.

== Changelog ==

= 1.0.1 =
* Recover missing scan tables and report scan-start database failures directly.

= 1.0.0 =
* Initial evidence-first scanner, reports, integrations, audit history, and login protection.
