# TODO

## P1 - Offline Public Breach Dataset Matching For NTLM Hashes

### Goal
Add support for comparing HashCrush NTLM hashes against the official offline Have I Been Pwned Pwned Passwords NTLM corpus on a machine with no internet access, then expose the match results in the UI, analytics, and exports.

### Scope
- NTLM only for v1.
- Support hashes imported through:
  - `Windows pwdump`
  - NTLM `hash_only`
- Do not call the HIBP API from HashCrush.
- Do not store the entire downloaded HIBP corpus inside the main Postgres app database.
- Surface whether a hash appears in the public corpus and the observed prevalence count.
- Do not attempt breach attribution. HIBP Pwned Passwords does not map hashes back to named breaches.

### Why This Needs A Separate Design
- HashCrush stores the original hash encrypted at rest in `Hashes.ciphertext`.
- `Hashes.sub_ciphertext` is a keyed blind index, not the raw hash.
- That means direct SQL joining between local hashes and the HIBP NTLM corpus is not possible.
- Matching must happen in a controlled offline scan step that decrypts local NTLM hashes on the server, compares them to a local reference dataset, and persists only the result.

### Proposed Architecture

#### 1. Local Reference Dataset Outside Postgres
Store the downloaded HIBP NTLM corpus in a local indexed format under HashCrush-managed storage, for example:
- `storage/hibp/ntlm/`

Recommended v1 on-disk format:
- prefix-sharded flat files by first 5 hex chars
- filename example:
  - `ABCDE.txt`
- file contents:
  - `1234567890ABCDEF1234567890A:42`
  - where the line format is:
    - `suffix:prevalence_count`

Why this format:
- easy to build offline
- easy to inspect and verify
- mirrors the HIBP range model
- avoids loading the entire corpus into memory
- avoids bloating the primary app database

Possible later optimization:
- move the reference store to SQLite, LMDB, or another embedded local key-value/indexed format if scans become too slow

#### 2. Reference Dataset Metadata In Postgres
Add a small metadata table for loaded offline datasets, for example:
- `reference_datasets`

Suggested fields:
- `id`
- `name`
- `kind` (`hibp_ntlm`)
- `version_label`
- `source_filename`
- `record_count`
- `loaded_at`
- `storage_path`
- `notes`

Purpose:
- show whether the offline corpus is loaded
- show when it was last refreshed
- support future additional local reference datasets

#### 3. Persisted Match Results In Postgres
Add a results table, for example:
- `hash_public_exposures`

Suggested fields:
- `id`
- `hash_id` FK to `Hashes`
- `source` (`hibp_ntlm`)
- `matched` bool
- `prevalence_count` int
- `checked_at`
- `dataset_id` FK to `reference_datasets`

Suggested constraints/indexes:
- unique on `(hash_id, source, dataset_id)`
- index on `(source, matched)`
- index on `hash_id`

Purpose:
- cache the offline match result for UI/analytics/export use
- make repeated UI queries cheap
- avoid rescanning every time a page loads

### CLI / Operational Workflow

#### 4. Offline Dataset Loader Command
Add a CLI command, for example:
- `python3 hashcrush.py hibp load --source /path/to/hibp-ntlm.txt`

Responsibilities:
- validate the downloaded corpus format
- normalize NTLM hashes to uppercase 32-char hex
- build the local prefix-sharded index under storage
- write atomically to avoid partial datasets
- register/update the dataset metadata row
- log counts and failures clearly

Optional support:
- compressed source file input if the official download format changes

#### 5. Offline Scan Command
Add CLI commands such as:
- `python3 hashcrush.py hibp scan --hashfile-id 123`
- `python3 hashcrush.py hibp scan --domain-id 5`
- `python3 hashcrush.py hibp scan --all`

Responsibilities:
- only consider `Hashes.hash_type == 1000`
- scan unique `Hashes` rows, not account rows
- decrypt `Hashes.ciphertext`
- normalize the NTLM hash
- look it up in the local reference index
- write/update `hash_public_exposures`

Important behavior:
- because `Hashes` are globally deduplicated, a single match should benefit every hashfile and account row linked to that `hash_id`

#### 6. Background Job Integration
Do not run large breach scans inline in web requests.

Add background operations for:
- scan one hashfile
- scan one domain
- optionally scan all NTLM hashes after a dataset refresh

Desired UX:
- queue the scan
- show progress in the existing background-operation UI
- persist status like other async work

### UI / Reporting

#### 7. Hashfile Detail Page
Extend the hashfile detail page with:
- `Publicly Exposed NTLM Hashes`
- `Accounts Using Publicly Exposed NTLM Hashes`
- dataset freshness info
- scan button for admins
- export button for affected accounts

Only show this section when:
- the hashfile contains NTLM-compatible content
- and/or a scan result exists

#### 8. Domain / Analytics Views
Add scope-level posture metrics:
- publicly exposed unique NTLM hashes
- account rows linked to publicly exposed NTLM hashes
- percent of NTLM account rows found in the offline breach corpus

Add exports:
- affected account rows in current scope
- filenames should follow the existing analytics naming pattern and include the download date

Example filename:
- `public_breach_matched_accounts_domain_3_2026-04-01.txt`

#### 9. Search Enhancements
Add a search or filter option such as:
- `Public breach matched only`

Useful outputs:
- username
- domain
- hashfile
- hash
- plaintext if recovered
- public prevalence count

### Security / Data Handling

#### 10. Security Constraints
- keep the raw HIBP corpus outside the main transactional database
- never expose raw dataset internals directly in public routes
- keep all matching server-side
- do not weaken existing encrypted-at-rest storage for local hashes
- only persist the boolean match result and prevalence count in app tables

#### 11. Operational Refresh Process
Document the offline workflow:
1. download the official HIBP NTLM corpus on an internet-connected machine
2. transfer it securely to the HashCrush machine
3. run the loader command
4. run the scan command
5. review updated UI/analytics/export results

### Implementation Notes

#### 12. Suggested File/Module Additions
- `hashcrush/hibp/service.py`
- `hashcrush/hibp/index_builder.py`
- `hashcrush/hibp/scanner.py`
- `hashcrush/hibp/tasks.py`

Likely existing touchpoints:
- `hashcrush/models.py`
- `hashcrush/db_upgrade.py`
- `hashcrush.py`
- `hashcrush/analytics/routes.py`
- `hashcrush/templates/hashfiles_detail.html`
- `hashcrush/templates/analytics.html`
- `hashcrush/searches/routes.py`
- `hashcrush/templates/search.html`

#### 13. Phased Delivery
Phase 1:
- loader
- local prefix index
- match results table
- CLI scan

Phase 2:
- hashfile detail UI
- analytics stats
- exports

Phase 3:
- domain-wide scan actions
- background queued scan operations
- search filter integration

### Open Questions For Later
- exact format of the official offline NTLM corpus at ingestion time
- whether prefix-sharded text files are fast enough at the expected dataset size
- whether prevalence count should be shown to all authenticated users or admins only
- whether rescans should overwrite old results or keep per-dataset history
