# PhishTriage Product and Engineering Roadmap

This document captures the next major UX and functionality enhancements for PhishTriage, with a focus on making the app more useful for analysts during phishing investigations.

## Goals

- Reduce UI friction for analysts
- Replace source-centric workflows with investigation-centric workflows
- Improve actionability of VT and future AlphaMountain data
- Add takedown support for Google Cloud Storage-hosted phishing pages
- Create a roadmap that can be turned into GitHub issues and milestones

## Product Direction

The app should evolve from a set of separate technical tabs into a unified analyst workspace with three main surfaces:

1. `Investigations`
2. `Investigate`
3. `Actions`

### Investigations

This is the analyst's main operating view. It should replace the current Queue and Database split.

Key principles:

- Show one unified list of scan records
- Use filters instead of separate tabs for lifecycle state
- Keep table columns high-signal and concise
- Move rich context into a detail panel or expandable row

Recommended filters:

- `pending`
- `complete`
- `malicious`
- `suspicious`
- `needs review`
- `takedown drafted`

Recommended summary columns:

- URL
- verdict
- score
- hosting provider
- status
- submitted time
- actions

Recommended detail sections:

- URL and sanitization
- urlscan
- VirusTotal
- AlphaMountain
- takedown/reporting
- analyst notes

### Investigate

This should replace the current split between Search and VT Lookup.

The workflow should start from an analyst question:

- Have we seen this before?
- What does external intelligence say?
- Is this part of a pattern or campaign?

Recommended input types:

- URL
- domain
- IP

Recommended results layout:

- top summary banner
- local DB matches
- urlscan history
- VirusTotal enrichment
- AlphaMountain enrichment
- related indicators and pivots

Recommended summary content:

- seen before / first seen
- hosting provider
- internal verdict summary
- VT summary
- AlphaMountain summary
- takedown candidate status

### Actions

This is where analysts should act on the investigation.

Recommended actions:

- copy IOC bundle
- re-run enrichment
- generate Google Cloud abuse draft
- track takedown state
- add analyst notes
- export evidence

## Functional Enhancements

### 1. Merge Queue and Database

Problem:

- Queue and Database are overlapping list views
- Analysts have to bounce between tabs unnecessarily

Approach:

- Remove Queue as a separate tab
- Promote Database into `Investigations`
- Use filters for lifecycle states instead

Benefits:

- simpler workflow
- less duplicated UI
- better alignment with how analysts think

### 2. Improve Database Usability

Problem:

- The current table is overloaded
- Analysts can only effectively consume around 10 visible columns

Approach:

- Keep the table narrow
- Add a detail panel or expandable row
- Group deep fields into logical evidence sections

Benefits:

- better readability
- less horizontal scrolling
- more usable enrichment data

### 3. Make VT Data Actionable

Problem:

- VT data is visible but not operationally useful enough

Approach:

- present VT as an evidence block, not just raw fields
- add pivots by domain, IP, ASN, and threat names
- support one-click copy and enrichment workflows

Recommended VT actions:

- copy VT indicators
- search same domain in local DB
- search same IP in local DB
- draft takedown using current evidence

### 4. Add AlphaMountain

Goal:

- add AlphaMountain as a second threat intelligence source

Potential data points:

- URL classification
- domain reputation
- IP reputation
- risk score
- categories
- impersonation probability
- raw intelligence payload

Recommended implementation strategy:

- start with env/config and backend helper methods
- store raw response and a small parsed subset
- render as a dedicated evidence card
- optionally feed AlphaMountain into scoring later

### 5. Redesign Search

Problem:

- current Search is source-driven rather than analyst-driven

Recommended approach:

- search local DB first
- optionally enrich with urlscan, VT, and AlphaMountain
- render one digestible result rather than multiple disconnected outputs

Best direction:

- replace Search and VT Lookup with one `Investigate` workflow

### 6. Add Google Cloud Storage Takedown Workflow

Problem:

- Analysts need a structured way to report malicious `storage.googleapis.com` URLs

Recommended MVP:

- detect Google Cloud Storage hosting
- generate a takedown draft with supporting evidence
- let the analyst copy the draft and open the Google abuse form

Official form:

- `https://support.google.com/code/contact/cloud_platform_report?hl=en`

Recommended evidence in the draft:

- malicious URL
- original URL
- verdict and score
- urlscan result link
- screenshot link
- abuse summary
- timestamps

Recommended future state:

- track takedown status in-app
- maintain a takedown queue

## Technical Roadmap

## Phase 1: Investigations Foundation

### Backend

- extend `/api/scans` with optional filters:
  - `status`
  - `verdict`
  - `provider`
  - `has_review`
  - `limit`
- return derived fields:
  - `hosting_provider`
  - `has_sanitization`
  - `has_takedown_candidate`

### Frontend

- merge QueueTab and DBTab into `InvestigationsTab`
- reduce visible columns
- add a detail panel / expandable investigation view

## Phase 2: Investigation Workflow

### Backend

- add local search endpoint
- add unified investigate endpoint

Suggested endpoints:

- `GET /api/investigate/local?q=...`
- `GET /api/investigate?q=...`

Suggested investigate response:

```json
{
  "query": "example",
  "query_type": "url",
  "summary": {},
  "local_matches": [],
  "urlscan_matches": [],
  "vt": {},
  "alphamountain": {}
}
```

### Frontend

- replace Search tab with `InvestigateTab`
- merge VT Lookup into this workflow
- add summary banner and source sections

## Phase 3: AlphaMountain Integration

### Config

- add `ALPHAMOUNTAIN_API_KEY`

### Backend

- add helper methods:
  - `_am_lookup_url(url)`
  - `_am_lookup_domain(domain)`
  - `_am_lookup_ip(ip)`

### Persistence

Recommended minimum:

- `am_raw`

Recommended richer model:

- `am_url_score`
- `am_domain_score`
- `am_ip_score`
- `am_categories`
- `am_impersonation_probability`
- `am_raw`

### Frontend

- add AlphaMountain evidence card

## Phase 4: Takedown Workflow

### Backend

Add a new table:

`takedown_requests`

Suggested fields:

- `id`
- `scan_uuid`
- `provider`
- `target_url`
- `hosting_provider`
- `draft_text`
- `evidence_json`
- `status`
- `submitted_at`
- `submitted_by`
- `reference_id`

Suggested endpoints:

- `POST /api/takedown/draft/{uuid}`
- `GET /api/takedown`
- `POST /api/takedown/{id}/status`

### Frontend

- add `ActionsTab` or `TakedownTab`
- show draft preview
- allow copy
- allow open-to-form workflow
- allow status updates

## Phase 5: Analyst Productivity

Potential additions:

- copy IOC bundle
- analyst notes
- related indicator pivots
- exportable evidence bundle
- persisted `review_required` events

## GitHub Issue Backlog

## Priority 1

1. Merge Queue And Database Into A Single Investigations View
2. Add Investigation Detail Panel For Scan Rows
3. Reduce Investigations Table To High-Signal Summary Columns
4. Add Hosting Provider Detection To Scan Records
5. Create Local DB Search Endpoint
6. Replace Search Tab With Unified Investigate View

## Priority 2

7. Fold VT Lookup Into The Investigate Workflow
8. Add Investigation Summary Banner
9. Add AlphaMountain Config And API Client
10. Persist AlphaMountain Enrichment Data
11. Add AlphaMountain Evidence Card To UI
12. Incorporate AlphaMountain Signals Into Verdict Logic

## Priority 3

13. Add TakedownRequest Table
14. Generate Google Cloud Abuse Drafts For `storage.googleapis.com` URLs
15. Add Takedown Actions To The UI
16. Add Takedown Queue / Actions View

## Priority 4

17. Add Copy IOC Bundle Action
18. Add Analyst Notes To Investigations
19. Add Related Indicator Pivoting
20. Add Exportable Evidence Bundle

## Optional / Later

21. Persist `review_required` Events Before Submission
22. Add Bulk Investigate Workflow
23. Add Cross-Source Correlation Summary

## Suggested Milestones

### Milestone 1

- Issues 1-6

### Milestone 2

- Issues 7-12

### Milestone 3

- Issues 13-16

### Milestone 4

- Issues 17-23

## Best MVP Sequence

If the goal is fast analyst value, build in this order:

1. Merge Queue + Database into Investigations
2. Add detail panel
3. Add local DB search
4. Replace Search with Investigate
5. Add AlphaMountain config and client
6. Add Google Cloud abuse draft generation

## Notes

- The current UI already has the beginning of column configurability, but the long-term answer is not “more columns.”
- The long-term answer is:
  - fewer summary columns
  - better detail views
  - one coherent investigation workflow
  - explicit analyst actions
