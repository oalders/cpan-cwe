# cpan-cwe

Classify the CVEs [CPANSec](https://security.metacpan.org/) has published, by
[CWE](https://cwe.mitre.org/), and rank the weaknesses that show up most often
in the Perl and CPAN ecosystem.

This is the data pipeline behind a [perl.com](https://www.perl.com/) blog post.

## Data source

CPANSec is the CVE Numbering Authority (CNA) for Perl and CPAN. Every CVE it
publishes is announced on its public **cve-announce** list:

<https://lists.security.metacpan.org/cve-announce/>

That list is a single, self-contained source for this analysis:

- every message *is* a CVE CPANSec issued as a CNA, so the set matches "CVEs
  issued by CPANSec" exactly — no filtering by CNA needed; and
- each advisory carries a `Problem types` section listing its CWE(s), so the
  weakness classification comes straight from the advisory.

No other feed is consulted.

## Method

- `bin/collect-cves` walks the monthly archive indexes, follows each message,
  and pulls the CVE id (from the subject) and the CWE(s) (from the `Problem
  types` section) into `data/records.json`. Follow-up (`Re:`) posts are skipped
  and the first announcement of each CVE wins.
- `bin/rank-cwes` counts, ranks, and rolls the CWEs up into editorial themes,
  and writes `data/cwe-by-cve.csv` (one row per CVE).
- `bin/build-report` renders `data/report.html` (bar chart + rollup + full
  table).

### A note on counting

A CVE can be tagged with more than one CWE. The ranking counts **how many CVEs
carry each CWE**, so a CVE with two CWEs contributes to both — the totals across
CWEs therefore add up to more than the number of CVEs. The category rollup in
`categories.json` is *editorial*: an approximate grouping meant for reading, not
an official taxonomy. Edit it to taste.

## Usage

```bash
cpanm --installdeps .        # or: cpm install -g --cpanfile cpanfile

# default window: 2026-05 through the current month
perl bin/collect-cves
perl bin/rank-cwes
perl bin/build-report

# custom window (YYYY-MM start [end])
perl bin/collect-cves 2026-05 2026-08
```

## Output

| File | What |
|------|------|
| `data/records.json`    | one record per CVE: id, date, subject, CWE list |
| `data/cwe-by-cve.csv`  | flat table: cve, date, cwe ids, cwe names, subject |
| `data/report.html`     | standalone visual report |

The `data/` snapshot committed here is regenerable at any time by re-running the
pipeline; numbers move as CPANSec publishes more advisories.
