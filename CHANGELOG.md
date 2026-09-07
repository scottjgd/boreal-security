# Changelog

## 1.0.3

- Introduced a cohesive security operations dashboard with a clearer evidence score and scan state.
- Redesigned findings, history, audit, and settings screens for faster scanning and stronger hierarchy.
- Added a focused Pro feature story without weakening the usefulness of the Free edition.

## 1.0.2

- Replaced the reserved scan cursor column name so the scans table installs on MariaDB and MySQL.
- Bumped the database schema so affected installations recreate the corrected table definition.

## 1.0.1

- Recreate missing scan tables even when the stored database version is current.
- Report scan-start database failures directly instead of starting an invalid batch.

## 1.0.0

- Added evidence-first bounded scanning and persistence.
- Added official WordPress core checksum verification.
- Added login throttling, audit history, exports, Site Health, and WP-CLI.
