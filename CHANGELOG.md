# Changelog

## 0.16.2 - 2026-10-29 - A report a responder can act on

From a review of a full synthetic case's report, read as a responder would:

- **Reading order.** `report.md` now follows the order the guide reads a
  report: verdict, what to do next, evidence gaps, then findings. The separate
  "Detections not evaluated" list is gone; it repeated the gaps.
- **What to do next**, in both reports, by verdict. It quotes the platform
  playbook's do-not list and the credentials it says to treat as exposed, and
  links the playbook read with the verdict. The link used to be the last line
  of the HTML.
- **Gaps say what they need.**
  - A detection that was not evaluated names the step that failed and its
    command, or the file it had nothing to scan, and how to close the gap. It
    used to say "required evidence not in case".
  - Detections that need the same thing are one gap.
  - A missing evidence class names the plan's steps that would provide it and
    the flag each needs.
  - "earliest on-box log line n/a" reads as what it means.
- **Findings.**
  - Each hit names the command and line that produced it.
  - Each finding shows its pack's confidence, and unverified where it is.
  - CVEs link to the site.
  - A hit no longer repeats its finding's title or prints "no timestamp".
  - In the HTML, "no hit" is a neutral grey; green read as good news.
- **Custody.** The case manifest's sha256 is in `findings.json` and in both
  report headers.
- **Fixed: evidence classes no step could provide.** Junos's JMRT integrity
  check counted only as a bundle, and F5's System Scanner as memory, so their
  integrity gap could never close. A step may now declare `provides`, which
  only those two do, as their documented purposes state. Manifests record each
  step's classes. Classes no step provides (Check Point config and filesystem,
  F5 filesystem, IOS XE persistence) stay gaps, and their hint gives the
  ingest route.
- **The guide** has a worked example: a synthetic Junos case read line by line,
  with what to tell the incident lead. A test regenerates the case and fails
  if any quoted line no longer matches what the tool prints.

## 0.16.1 - 2026-10-29 - VirusTotal, links only

- **Every published address, domain, URL and hash** in the indicator tables
  links to VirusTotal's own page for that value.
- **Nothing from a VirusTotal report is copied** into the repository or the
  site: no verdict counts, dates or labels. That is the maintainer's decision
  under VirusTotal's terms, recorded in CLAUDE.md.
- **The indicator note** says that a VirusTotal page with no detections does
  not make a value safe.

## 0.16.0 - 2026-10-29 - Threat intel: trends, overlap, infrastructure, hardening

- **Exploitation by year.** A grid of the CVEs each actor record is tied to, by
  the year CISA added them to KEV, on the validated one-hue ramp. Every cell
  opens the CVE. It is labelled as dating CISA's listing, not the start of
  exploitation; the CVE records quote the primary sources' own earliest dates.
- **Where actors overlap.**
  - Pairs of actors that share CVEs or platforms, with the CVEs linked.
  - Values that appear in more than one publisher's set.
  - /24 neighbourhoods holding addresses from more than one set. That grouping
    is the toolkit's arithmetic and says nothing about who controls a block.
  - The section says plainly that this is shared targets, not shared identity:
    clusters are never merged unless the reporters equate them.
- **Infrastructure by record.** For each actor or implant that a set is tied
  to: its addresses, file hashes, accounts and other indicators, then how many
  its publisher calls actor-controlled, and how many have no stated role. A
  publisher that gave no roles is shown as silence, not as "0% actor-controlled".
- **Hardening for each actor and implant**, in two kinds that are never mixed:
  - controls whose own source names the record, an alias or one of its
    implants;
  - controls whose source ties them to a CVE that the record is tied to. This is
    a join of two records and is labelled as one.
  The chart ranks both, and every actor and implant drawer lists the controls
  under the same two headings.
- A browser test pins the four sections and the drawer's split.

## 0.15.2 - 2026-10-29 - The guide, end to end

- **A workflow figure** opens the guide. It shows the order a case moves in
  (preserve, plan, collect or ingest, case folder, analyze, read the report,
  decide, respond) and the two loops that matter: a gap you can close goes back
  to collection with break-glass last, and `NO-INDICATORS-FOUND` closes the
  gaps before the case.
  - The generator draws it as inline SVG from the site's own tokens, so it
    follows both themes. On a phone it scrolls inside its frame rather than
    shrinking.
  - A `<!-- figure:name -->` marker places it. `--check` fails on a marker with
    no drawing, and a browser test pins the figure.
- **New sections**, from a review of what a responder needs and the guide did
  not say:
  - **The case folder:** every path, what it holds, and the manifest's hash
    chain.
  - **When a step fails:** where the status is recorded, and how `--replay`
    lays out recordings.
  - **Memory first, by the safest route:** a hypervisor snapshot for virtual
    appliances; the vendor's core dump, break-glass, for hardware.
  - **Clocks:** each platform's clock step, and Ivanti's lack of one.
  - **`--baseline`.**
  - **Hunting off the box.**
  - **Using the threat intelligence:** roles, shelf life, two confidences,
    defanged versus refanged.
  - **Exploited CVEs and BOD 26-04:** what the forensic triage flag's "No"
    means.
  - **After triage:** the response playbook's order, what to do with a
    suspicious verdict, and wording a verdict for others.
  - **A table of terms.**

## 0.15.1 - 2026-10-29 - Charts that say what they count

- **Confidence charts.**
  - **Coverage page.** High and medium were two near-identical slates, and low
    or unverified used the critical red that means "confirmed" elsewhere. They
    are now one slate ramp, light to dark, validated as an ordinal scale against
    both themes, with ink chosen per step. Detections, the largest library, is
    on the chart now: each detection carries its pack's confidence.
  - **Artifact groups.** The one bar on each platform row counted volatility
    but sat under the Value and Confidence headers. Each of those columns now
    has its own small bar, under its header and named in its label.
- **Legends.** Every distribution bar (tiers, volatility, priority) now has a
  legend naming each segment with its count and share, so a segment too narrow
  for a label is never anonymous.
- **Hunts.** The data-sources bar alternated two blue-greys and dropped the
  names of small segments. It is labelled bars now, one per kind of data, beside
  platform and confidence charts. Rows still filter on click.
- **Stats and trends** on Detections and Hardening. A collapsible panel with:
  - exploited CVEs by the year CISA added them to KEV, split by whether the
    toolkit has a detection (or a hardening control) naming each one;
  - counts by platform, evidence class, where detections run, type and the
    CVEs with the most detections;
  - for hardening: priority, category, platform, the kind of source each
    control cites, and the controls whose sources tie them to the most CVEs and
    campaigns.
  The two-part split's colours are validated as a pair in both themes.
- **Cards.** Badges now share the id line instead of the title's, so a title
  gets the card's full width. Two badges once squeezed a CVE id into three
  lines and left most of the card blank.
- **Cut-off text.** Weakness names are shown in full; they used to be cut at 32
  characters. Long filter labels and chips wrap instead of ending in "…", and
  the CVE page's actor chips can no longer run past their column.
- Two browser tests pin these.

## 0.15.0 - 2026-10-29 - Testing a silence against what the device did

- **`analyze --activity`.** A gap in the forwarded stream used to be listed
  with "compare with NetFlow", but many owners have no NetFlow. The gap is now
  tested against any record of what the device did, from a source it does not
  control:
  - sign-ins through it (identity provider or RADIUS);
  - sessions from its inside address on the next firewall;
  - connections from its VPN pool in EDR;
  - flows, where they exist.
- **What counts as an event.** One per record or line. JSON, JSON lines and
  CSV are read by their time field: the SIEM names, Okta's `published`,
  Entra's `createdDateTime`, Zeek's `ts` and others, or name it with
  `--activity-field`. Plain files are read by the first ISO time on each line.
  `--activity-match` keeps the records naming the device, as a whole token, so
  `192.0.2.1` does not match `192.0.2.10`.
- **New possible indicator: `offbox-silent-while-active`.** It fires when three
  or more events fall inside a gap, not counting five minutes at each end.
  - It sits in the `offbox-logs` class and links to EDGE-HUNT-0009.
  - This is the case where an intruder stops local logging and forwarding
    together. Both copies then still agree, and a gap with the device busy is
    the only evidence left.
  - A gap the export spans with no events is reported as quiet there too.
  - A gap the export does not span is not counted as tested.
  - A forwarded copy whose times have no year (raw syslog) cannot be placed.
    It is reported as not evaluated, with how to export it instead.
- **Without `--activity`, nothing changes.** Gaps are listed and not scored. An
  `offbox-activity-missing` evidence gap now says which exports would test
  them, instead of naming only NetFlow.
- **Wording.** EDGE-HUNT-0009, the guide, the report, the standing gap's
  advice and the site's verdict ladder now name these sources, with NetFlow
  as one of them. When only off-box checks fire, the verdict says which: the
  copies disagree, or forwarding went quiet while the device was active.
- Internals: times now record whether the source stated a zone, and a gap
  tested against an unzoned source says that times without a zone were read
  as UTC. The record readers for the forwarded and activity exports share one
  parser. Eight tests cover the new paths.

## 0.14.1 - 2026-10-28 - Repeated messages and the off-box verdict

- **Fixed: a deletion that included a repeated message was missed.** The
  off-box comparison counted messages as a bag. A deleted logout "found" a copy
  of the same logout hundreds of lines away, so it looked kept. That split the
  deleted stretch into pieces shorter than the five-line minimum. A synthetic
  Junos log with 12 lines deleted came back `NO-INDICATORS-FOUND`.
  - **The fix.** The copies are now lined up in order, like a patience diff.
    Messages that occur once in each copy anchor the comparison and cut it into
    short stretches. A repeated message pairs only with a copy in its own
    stretch.
  - **Loose pairs.** Those pairs, and once-only lines the collector received
    out of order, are `loose`: they neither end a run nor count toward one.
  - **Runs end where they end.** Inside a stretch, the matching lines at
    each end are paired first, as a diff does. A logout both copies keep,
    just after a run, then meets its own copy, and the run's end time is the
    last line actually missing.
- **Fixed: rotation with repeated messages.** The same bag counting let a
  rotated-away logout pair with a later copy on the box. That pulled rotated
  lines into the comparison. Depending on spacing, it raised false "gone from
  the box" runs or reported the copies as not comparable. The comparison now
  starts at the first anchored line, and the leading stretch pairs from the
  end.
- **Not comparable, said plainly.** A log of nothing but a few repeated
  messages has no anchors, so it is not compared. The reason now says so.
- **Known limit.** When a deleted stretch and a never-forwarded stretch touch,
  a repeated message in one can pair with a copy in the other, and each run
  counts fewer lines than it holds. This is stated in `offbox.py`.
- **Verdict wording.** When only the off-box comparison fires, the verdict no
  longer reads "often exploitation attempted". It says that the SIEM's copy and
  the box disagree, and points to the benign causes listed in each finding. The
  site's verdict ladder and the guide's tier table say the same.
- Three regression tests pin each fix: repeated messages in a deleted stretch,
  rotation with repeated messages, and lines received late.
- **Ingest-only reports.** A case built only from exports is the normal path
  for Ivanti and SonicWall, which have no collection profile. Its report
  printed `Profile: None` and `Collected: to UTC`. It now says there was no
  live collection. Stream gaps of whole hours read "1 h", not "1 h 0 min".

## 0.14.0 - 2026-10-28 - The SIEM's copy against the box

- **`analyze --forwarded`.** Give the analyzer the device's syslog as the SIEM
  or collector received it: raw lines, JSON (array or lines) or CSV with a
  `Message` field. It lines that copy up with the logs on the box. This is the
  first off-box hunt the toolkit runs in code: EDGE-HUNT-0027, plus the gap
  list from EDGE-HUNT-0009.
  - **By message, not by clock.** Each line is reduced to the message after
    its syslog header. The comparison runs only between the first and last
    line the copies share. Rotation at either end, and a device clock in
    another time zone, are not read as deletion. Lines older than anything on
    the box are reported as older than the box.
  - **Two possible indicators.** It flags runs of five or more forwarded lines
    gone from the box, and runs of local lines the SIEM never received, with
    shared lines on both sides of each run. They sit in their own evidence
    class, `offbox-logs`. Each finding names its benign causes: a level or
    facility logged at one end only, lost UDP datagrams, a collector outage.
  - **Not evaluated, never "all missing".** That applies when the copies share
    fewer than 20 lines (a different forwarded format) or when most of the span
    is one-sided (a level difference). It shows as an `offbox-not-compared`
    evidence gap.
  - **Stream gaps are listed, never scored.** Each is measured against the
    stream's own cadence and flagged when it falls in the `--window-start`
    window. A quiet night is not an indicator without NetFlow.
  - **Exports in either order.** A newest-first export is put back in time
    order. Each export's sha256 is recorded in `findings.json`.
  - **In the reports.** `report.md` and `report.html` have an "Off-box
    comparison" section. The findings link to the hunt record.
- **Docs.** The guide, README, roadmap and both hunts describe the new option.
  CLAUDE.md's "the analyzer never runs hunts" now names this one coded
  exception and how it behaves.

## 0.13.0 - 2026-10-28 - Keeping quotes and exploitation dates current

- **Quote check.** New `artifacts/scripts/check_quotes.py` re-fetches every
  page a record quotes and confirms the quote is still there word for word.
  That's 274 quotes across exploitation dates, hunts and hardening controls.
  - It forgives only what a faithful copy can differ in: whitespace, quote
    marks, dashes, and the spacing a link or a PDF bullet leaves.
  - A JavaScript-built knowledge base is listed as needing a rendered check,
    never as changed.
  - A quote read through a summariser that now matches word for word is listed
    as ready to become `read: direct`.
  - A monthly workflow (`quote-check`) runs it and opens an issue when a quote
    is gone. It never commits.
- **First run.** 196 quotes matched, none were gone, 46 need a rendered check
  and 32 were unreachable from the sandbox. It found five hardening quotes
  from cyber.gc.ca carrying a full stop the page does not have; they are list
  items. Corrected and recorded in `docs/VERIFICATION.md`.
- **Exploitation dates stay current.** The weekly advisory-watch report has a
  new section listing every CVE on the site with no record in
  `artifacts/intel/exploitation.yml`. It keeps the issue open until each one
  has been searched.

## 0.12.1 - 2026-10-28 - Local logs against the forwarded copy

- **New hunt, EDGE-HUNT-0027: local logs no longer match the copy the SIEM
  received.** A reader suggested it on LinkedIn.
  - It lines up the SIEM's copy of a device's syslog with the logs left on the
    box. It flags lines the SIEM holds that are gone locally, local logs that
    begin after the exploit window, and clearing events in the forwarded copy.
  - Sources:
    - AA25-239A tells defenders to review forwarded logs for "Evidence of
      clearing locally stored logs".
    - Volexity found an Ivanti appliance in January 2024 whose "logs had been
      wiped and logging had been disabled".
    - Talos saw the 2023 IOS XE attacker "clearing logs and removing users".
  - It sits beside EDGE-HUNT-0009, not in place of it. SPAWNSLOTH disabled
    local logging and forwarding together, which leaves both copies matching.
  - It is linked from the records for CVE-2023-46805, CVE-2024-21887 and
    CVE-2023-20198.

## 0.12.0 - 2026-10-28 - When exploitation began, quoted

- **Exploitation dates for every CVE.** No feed records when exploitation of a
  CVE began. New `artifacts/intel/exploitation.yml` quotes what primary sources
  say for all 77 CVEs: 129 reports from vendors, the teams that saw the
  exploitation, and government agencies.
  - **Earliest activity.** `earliest` is the earliest activity a source dates,
    only as precise as the source. 39 reports carry one, covering 36 CVEs.
  - **Statement date.** `stated_on` is when the statement was published, taken
    from bylines and revision histories.
  - **What was read.** Each CVE lists what was read, including dates that were
    rejected and why. Four CVEs have no report that dates exploitation, and the
    record says that is not a claim they were not exploited.
  - **Checked.** Every one of the 129 quotes was checked against its page on
    2026-10-28. Details are in `docs/VERIFICATION.md`.
- **Exploited before the CVE record was published.** For 20 CVEs, a quoted
  source dates exploitation before CVE.org published the record. The comparison
  uses the end of the period the source gives, so "August 2023" is never read
  as earlier than it is.
- **On the site.** Each CVE's Dates section adds:
  - the earliest exploitation and every report of exploitation;
  - "What the sources say", with each quote, its date, how that date is known,
    and what was read.
  - CVEs dated before their record's publication also get a callout and a card
    badge.

  The CVE library also gains an "Exploitation dates" facet and two stats tiles.
  The export carries the reports.
- **Validator.** It checks the new schema and that each `earliest_words` sits
  in its quote. It also checks that dates are real calendar dates, that no
  `earliest` falls after its report's own date, and that every CVE is one the
  site shows.

## 0.11.0 - 2026-10-27 - CVE tab review

- **Forensic triage flag, read correctly.** KEV's "No" was shown as "not
  required". Every entry added before BOD 26-04 was issued (2026-06-10) reads
  No, so the old wording put "not required" on CVE-2024-3400.
  - A record now reads "flagged: 3 days and forensic triage", "not flagged"
    with its deadline, or "added before BOD 26-04".
  - It quotes the directive's own definition and says the flag sets a federal
    deadline rather than whether a device needs forensics.
  - Due dates set before the directive are marked as set under BOD 22-01,
    since revoked.
  - All 74 KEV records were checked against CISA's cisa.gov feed: no
    mismatch. The correction is recorded in `docs/VERIFICATION.md`.
- **Dates beyond KEV's.** Each record has a timeline: the CVE.org record's
  publication date and assigner, the date added to KEV, CISA's SSVC assessment,
  the federal due date and the publication dates of linked indicator sets.
  - Linked actors' first-seen dates are listed separately, as the actor's.
  - The record says plainly that no feed dates when exploitation began.
  - New `artifacts/watch/cve-records.yml` holds these fields, written by
    `advisory_watch.py --cve-records`, with a schema and a validator check.
- **Filters.** A card's "ransomware" and "forensic triage" badges filter the
  list, and so do its weakness chips. There is a new "Weakness (CWE)" facet,
  with names from the CNA's record.
- **Patterns across the CVEs shown.** A panel above the list follows the
  filters:
  - counts you can click to filter;
  - the weaknesses shared across CVEs and platforms;
  - the actors and implants tied to the CVEs, with their CVEs.
- **Each CVE record shows its relations.** It lists the other CVEs that share
  its weaknesses, and the CVEs related through an actor or implant.
- **Platforms tie back to their CVEs.** Platform cards and records show their
  CVE count and the CVEs themselves, and each Start tile links to them.

## 0.10.0 - 2026-10-27 - CVE records and BOD 26-04

- **A CVEs library.** It has one record per CVE: all 55 KEV entries on the ten
  platforms since 2024, 19 older or adjacent ones the repository cites, and 3
  the repository cites that KEV does not list. 77 in all.
  - Each record puts CISA's own fields beside everything the toolkit has for
    the CVE.
  - CISA's fields: date added, due date, ransomware use, CWEs, required action
    and the advisory links in KEV's notes.
  - What the toolkit has: detections with their tiers; the traces the artifact
    records call suspicious; collection plans, playbooks, hunts and hardening;
    and actors, implants and indicator sets.
  - A CVE with no detection says why, quoting the ledger decision.
  - Facets: platform, forensic triage, ransomware use, coverage and year added.
- **BOD 26-04 forensic triage.** CISA's KEV feed now carries `forensicTriage`,
  defined in CISA's schema as "'Yes' if this vulnerability requires forensic
  triage per BOD 26-04". 11 records are flagged; 10 of them are on watched
  platforms.
  - A flagged record lists the directive's six steps, from Scoping to
    Escalation Decision. Step names and target timelines are quoted from CISA's
    implementation guidance.
  - Beside each step is where the toolkit starts it: the platform record, the
    collection plan, the playbook, the CVE's detections and `edgetriage
    analyze`, then `report.html`.
  - The page says the links are the toolkit's suggestion, not the directive,
    and that the directive wins where the two differ.
- `artifacts/watch/kev-records.yml` replaces `kev_added` from 0.9.1. It holds
  CISA's fields, verbatim, written only by `advisory_watch.py --records` from
  catalog 2026.10.26.
  - The weekly watch reports any field that drifts.
  - The validator checks it against its new schema and against the ledger.
  - The re-read flag reads its dates.
- CVE mentions across the site (detections, hardening, hunts, artifacts, the
  guide, Coverage's KEV table, the search) open the CVE record. The search
  lists CVE records first.
- Start shows the CVE count and the count flagged for forensic triage.
- Fixed: the watcher's reference scan read artifacts' `cves`, which artifacts
  do not have; it now reads `seen_in`.

## 0.9.1 - 2026-10-27

A file ages when the world moves, not when the calendar does.

- **Re-read flag.** A record now says "may need a re-read" when its file was
  last committed before the newest advisory on a platform it covers. An
  advisory here is either a KEV entry (CISA's date added) or an indicator set.
  - The flag appears under "Last changed" in the record's quick facts.
  - Coverage replaces the "changed in 90 days" column with a count per
    library, a table of each platform's newest advisory, and the list of files
    to re-read.
  - Files that apply to every device are not compared.
  - Nothing is flagged today: every record file is newer than the newest
    advisory, CVE-2025-61624 for FortiOS, added 2026-10-16.
- **KEV dates in the ledger.** `kev_added` in `artifacts/watch/kev-watch.yml`
  holds CISA's date added for all 55 KEV entries on watched platforms since
  2024. They were parsed from catalog 2026.10.26 by the new
  `advisory_watch.py --dates`.
  - The weekly watch reports any drift between the feed and the ledger, and
    exits 10 so the issue opens.
  - The validator fails when a triaged CVE has no date under its platform.
- `.git-blame-ignore-revs` is honoured. A commit listed there (a reformat, a
  field rename) does not reset any file's date.
- Known limit: a commit is not a review. An unrelated edit after an advisory
  also clears the flag. The full answer is a `reviewed:` date per record,
  which waits until there are outside contributors.

## 0.9.0 - 2026-10-27 - site UX v2

The Claude Design handoff (UX assessment findings F1 to F38), built in three
steps. Step 1 holds the quick fixes:

- Contrast (F33): `--faint` is now used only for lines and decoration. Facet
  heads, table heads, counts, footers, ghost chips and section labels move to
  `--muted`. Light `--conf-mid` darkens to #5d7189, and filled bars use
  `--on-accent` (F36).
- The record drawer is a dialog (F16). Focus moves to its title on open and
  goes back to the row that opened it on close.
- A zero on a warning tile is no longer red (F12). The intel page shows "every
  record has one" when no implant lacks a detection.
- One short platform name (F24, F8). `PLATFORM_ABBR` in the generator feeds
  the pickers, the facet rail (full name on hover) and the actor matrix, and
  `--check` fails on a platform without one. Facet values keep catalog or
  total-count order, so they no longer reorder as other filters change.
- Guide section links are always visible, and each h3 has a "Copy link" button
  (F30).
- Touch targets under 760 px (F31).
- Words instead of coloured inset bars (F11): "unverified", "coverage gap" and
  "baseline" badges. `stable` volatility is the same colour in badges and bars.

Step 2 adds new views, built from data the repository already has:

- Header (F1, F32): one row with a "Search everything" box, and it stays
  sticky on phones. The subtitle and byline move to the Start hero.
- Start (F4, F5, F6):
  - A "How far to trust it" card: profiles run on a device, steps by source,
    and detections with Sigma rules or from unverified packs.
  - Count pills.
  - Platform tiles with a Plan / Detect / Respond / Harden readiness grid and
    Collect / Respond buttons.
  - A numbered before-you-touch box that holds the unvalidated warning.
  - A verdict ladder whose copy is tested against `analyze.verdict()`.
  - Step counts on every collection tier. The legend folds.
- Libraries (F7, F9, F10, F13, F34):
  - One-line ledes, with "About this library" for the rest.
  - Controls on one line, with Copy link.
  - Artifact rows grouped by platform under sticky headers. Descriptions are
    clamped, the locator is the row's link, and the columns follow the width
    of the results.
  - Filter words are marked.
  - A "Runs in" strip on detection cards.
- Record drawer (F15): quick facts, section chips, a "How it connects" box,
  tinted normal/suspicious boxes and an "N of M" position.
- Coverage and trust (F17-F21):
  - Trust tiles.
  - Confidence by library.
  - Indicator-set freshness.
  - A readiness scorecard with ten platforms and eight capabilities.
  - CSS-grid heatmaps with tier pips.
  - A gap ledger that says who each gap affects and what closes it.
  - A KEV section (`#coverage/kev`) built from the advisory-watch ledger: pack
    CVEs by year, why each exploited CVE has no pack, and the decisions table.
- Threat intel (F22, F23):
  - The timeline has one row per actor, with a reporter count and the build
    date marked. Indicator sets share a final lane.
  - The roles chart leads with how many published addresses are
    actor-controlled.
- Response (F25, F26):
  - The verdict lens shows step counts.
  - A case id keeps ticks per case. Each tick records its UTC time, which also
    goes into the Markdown export.
  - An "I have read these" box folds the do-not list.
- Collection plans (F27-F29):
  - A summary band with a confidence bar and a steps-per-tier strip.
  - Withheld steps say why.
  - The builder's unvalidated warning is `#b-warn`.
  - There is a "One line, for pasting into a ticket" option.
  - On narrow screens the builder comes first.
  - Fixed: a profile without SSH put a `#` comment inside the backslash-
    continued command, which cut it short.
- Guide: reading time in the contents rail and 32 px contents links.

Step 3 adds the larger pieces, and fixes from review:

- Search everything (F2). `/`, Ctrl+K or the header box opens one search
  across:
  - every library;
  - every collection step;
  - the guide;
  - the KEV ledger.

  Results are grouped by library, at most five in each, with an "All N" link
  into that library's filter. An address pasted defanged (`192.0.2[.]1`,
  `hxxps://`) finds the stored value. Esc closes the search before it closes
  a record.
- Last changed (F21). Each record's quick facts give the date its file was
  last committed, and Coverage lists the newest and oldest file in each
  library. The Pages workflow now fetches the full git history. A build
  without history shows no dates rather than guessed ones.
- Text alternatives for the charts (F35). The coverage heatmaps are tables
  with a label on every cell, and each timeline track describes itself. The
  KEV year chart and the steps-per-tier strip each have a sentence of text.
- `edgetriage analyze` now also writes `report.html` beside `report.md`, verdict
  first (F38). The page holds:
  - the verdict card and its status bar;
  - a grid showing each detection by evidence class and tier;
  - the evidence gaps, each with how to close it;
  - findings with their excerpts;
  - a strip with one block per collection step.

  It is one self-contained file: no script, no font, no request, and links
  only back to the published toolkit. Every value is escaped, because
  excerpts and sources come from a compromised device. Like `report.md`, it
  stays in the case folder.
- Dark mode is lifted off black. The page was `#121110`, and outlines were
  1.3:1 against cards, so cards and inputs disappeared. Cards now stand off
  the page, outlines are 2:1, and control borders are 3:1 (WCAG 1.4.11);
  `test_dark_theme_outlines_are_visible` holds those floors. The report's dark
  tokens match.
- With a record open, the page behind it is locked under a scrim at every
  width. There is one scroller, and the wheel no longer spills from the drawer
  into the page.
- Kept as they were, by the maintainer's choice:
  - the record drawer stays an overlay (the handoff's docked panel would add
    a second scroll region);
  - the light theme stays the default.

## 0.8.2 - 2026-10-27

Follow-ups from the KEV triage.

- PEERSTITCH (EDGE-PACK-0031) is now covered three ways, and the pack now has
  five detections:
  - Memory: new FortiOS steps dump the memory maps of miglogd and iked, and a
    check looks for Unit 42's anonymous 16 KB rwxp region.
  - Files: a `/data2/template` listing for the staged files.
  - Unit 42's YARA rule, with its hashes and URLs as EDGE-IOC-0017.
- PivotC2 (EDGE-PACK-0035, CVE-2025-25249): a new `/tmp` listing step finds
  SOCRadar's `/tmp/.i.js`. The CVE leaves the ledger.
- NetScaler: a core-file listing step flags packet-engine crashes for
  CVE-2026-8452.
- Ivanti 2024: Mandiant's BUSHWALK, CHAINLINE, LIGHTWIRE and WARPWIRE rules
  (FRAMESTING is omitted because its published string is ambiguous). There is a
  new BUSHWALK implant record (EDGE-IMP-0014) and a request check for
  `platform=SafariiOS`. CHAINLINE is added to the 2024 web-shell record.
- Hardening: FortiOS `private-data-encryption` (CVE-2019-6693) and removing
  fgfm access (CVE-2024-23113), both in Fortinet's own syntax.
- Hunt EDGE-HUNT-0026: Truesec's RADIUS pattern for CVE-2020-3259.

## 0.8.1 - 2026-10-27

- EDGE-PACK-0029: Ivanti Connect Secure CVE-2025-0282 and CVE-2025-22457 (UNC5221,
  SPAWN family, PHASEJAM, DRYHOOK, TRAILBLAZE, BRUSHFIRE). It has five
  detections: Mandiant's seven YARA rules, GTIG's /tmp and .bak file
  indicators, the SPAWN library names (possible), and the ICT events
  SYS32039/SYS32040. File detections need a VM snapshot, external ICT
  snapshot or image, and otherwise report not evaluated.
- EDGE-IOC-0014: nine MD5 values from GTIG's posts.
- The SPAWN implant record now lists its detections. Its gap now says what
  evidence is still needed.
- All 20 remaining KEV ledger entries are triaged against primary sources; none
  is deferred.
- New packs:
  - EDGE-PACK-0030: FortiCloud SSO abuse (CVE-2025-59718, CVE-2026-24858). Uses
    Fortinet's own log lines. Comes with two Sigma rules and EDGE-IOC-0015.
  - EDGE-PACK-0031: FortiOS auto-script traversal and PEERSTITCH
    (CVE-2025-61624, low). Uses a generalised crash-log check.
  - EDGE-PACK-0032: PAN-OS CVE-2025-0108 and CVE-2025-0111. Request shape and
    Threat IDs 510000/510001.
  - EDGE-PACK-0033: Ivanti CVE-2024-21893 SAML SSRF.
  - EDGE-PACK-0034: NetScaler CVE-2026-3055 and CVE-2026-8452 (low).
- EDGE-PACK-0003 now lists CVE-2025-68686.
- EDGE-IOC-0016: PivotC2 indicators (CVE-2025-25249).
- The ledger records decisions with a new `lab-only` value. Eight entries are
  no-indicators and one is out-of-scope.

## 0.8.0 - 2026-10-27

### Unvalidated collection profiles are flagged everywhere
No profile has been run against a real device or vendor virtual edition yet.
- Each profile carries `validated_on: []`; an entry needs a release, date and
  basis and a Device verification row in `docs/VERIFICATION.md`.
- `plan` prints a warning; `profiles` marks every unvalidated profile.
- A live `collect` asks the operator to type `UNVALIDATED`, or needs
  `--accept-unvalidated` without a terminal. The check is in the engine, so no
  front-end can skip it. Replays are not affected.
- The manifest records the validation state, and `analyze` reports an
  `unvalidated-profile` evidence gap.
- README, the guide (new "Unvalidated profiles" section), the site's Start page
  and Collection plans tab say the same. Each plan shows a "not yet run on a real
  device" badge, and the command builder says the collector will ask.

### Indicators
- EDGE-IOC-0013: AA25-239A. 86 addresses (including the advisory's two IPv6
  addresses) and the four SFTP-client hashes. Parsed from the joint advisory PDF
  (IC3 copy) and cross-checked against CISA's page. Three addresses that the PDF
  prints and CISA's current page does not are left out.
- EDGE-IOC-0012: the three addresses Palo Alto Networks publishes for
  CVE-2026-0322. The PAN-OS management-interface control now cites that advisory.
- New indicator type `ipv6`: validated, defanged on the site, exported as STIX.

### Advisory watch
- `artifacts/scripts/advisory_watch.py` compares CISA's KEV catalog with the
  packs and with a triage ledger (`artifacts/watch/kev-watch.yml`). It also
  re-hashes the publisher files behind the indicator sets.
- The weekly `advisory-watch` workflow posts anything untriaged to an issue. It
  never commits.
- The validator checks the ledger: references exist, and a CVE that gains a pack
  must leave the ledger.
- The first sweep seeded 22 KEV entries as `deferred`. Among them are Ivanti
  CVE-2025-0282 and CVE-2025-22457 and PAN-OS CVE-2025-0108, which have no pack
  yet.

### Provenance rule
- A government cyber authority's own publication now counts as documentation of
  what it recommends (CLAUDE.md).
- Four baseline hardening controls are restored to high after their sources were
  re-read. Two of them lost wording that no source supported.

## 0.7.0 - 2026-10-23

### Source verification, round 3
Every cited URL (155) and quote (111) and roughly 870 unquoted claims were
re-read against the primary source, with Firecrawl for pages earlier passes could
not render. 196 issues found and corrected (23 high-severity); each correction is
in `docs/VERIFICATION.md` with the verbatim passage it rests on. Highlights:
- Three earlier corrections were themselves wrong and are reversed: lina region
  count (NCSC: the count is not an indicator; the split text section is), the
  SonicWall fixed firmware (10.2.2.2-92sv, not 10.2.1.15-81sv), and UNC6148's
  confidence wording.
- Detections fixed: the NetScaler pitboss pattern now matches Rapid7's published
  form too; the FortiOS sslvpnd crash is a coded check that pairs crash-log rows
  instead of a one-line regex that could never fire; the FortiOS symlink check no
  longer flags the stock `custom -> /data2/custom_lang` link; SonicWall
  `ld.so.preload` fires only with more than 2 bytes (GTIG), via YARA; Check Point
  CVE-2026-93616 username indicator is an attempt (possible), per Check Point.
- New detections from primary sources, among them CISA's on-box LINE VIPER check
  (opt-in break-glass), the published OVERSTEP hashes, COATHANGER CLI checks from
  the MIVD/AIVD advisory, CVE-2022-42475 file indicators, IOS XE web-login and
  dirty r-xp checks, and Mandiant's TINYSHELL hunting rules.
- Attribution: UPSTYLE was attempted, not installed (Volexity, Unit 42); UTA0178
  is no longer an alias of UNC5221 (neither reporter equates them); UTA0218 adds
  Volexity's "moderate confidence" China-based assessment; hunts tagged to an
  actor cite a source that names it.
- Hardening: the F5 httpd control now follows F5's actual CVE-2022-1388 mitigation;
  FortiOS fixed releases updated for the CVE-2025-68686 bypass.

## 0.6.1 - 2026-10-23

### Response
- Each playbook is now one top-to-bottom timeline in the fixed order (preserve,
  contain, rotate, eradicate, recover, verify) with a phase bar to jump between
  phases.
- Verdict filter: pick the analyzer's verdict and only the steps it calls for
  stay open; the rest collapse to a greyed line naming the verdicts they need.
  The choice is in the URL (`#response/cisco-asa?verdict=SUSPICIOUS`). The
  validator keeps every `when:` a list of real verdicts.
- Checklist: tick steps as you go (kept in your browser, per platform), with a
  progress bar, Copy as checklist (Markdown for case notes), Print, and Clear.
- Links from each playbook to its collection plan, detections, hunts, threat
  intel, hardening and platform entry; commands render as code; a platform menu
  replaces the pill row on phones; credential rows stack on narrow screens.

### Threat intel
- Cards show indicator and pack counts; a "Published indicators" filter.
- The record panel opens with a jump bar (Indicators, Hunts, Response) and adds
  the hunts tied to the actor and the response playbooks for its platforms.
- Chart bars no longer cut their labels short; charts start collapsed on phones.

### Site
- Light theme by default, whatever the operating system prefers; dark only when
  the viewer picks it.
- Byline and footer credit Raymond DePalma and DePalma Research LLC, with LinkedIn
  links; README, NOTICE and pyproject carry the same.

## 0.6.0 - 2026-10-23

### Detections
- Rules and detections merged: every Sigma rule is attached to the pack
  detection it expresses (`sigma:`), or tagged `edge-dfir.standalone`; the
  validator fails on an unlinked rule. The Rules tab became a filter of
  Detections (`#detections?runs=siem`), and old `#rules` links still land.
- 14 new Sigma rules (25 in all) and 11 new packs (`EDGE-PACK-0018` to `-0028`) for CISA KEV
  CVEs on the ten platforms that had none, wherever a primary source publishes
  an indicator: ASA ArcaneDoor 2025-2026 (FXOS `lina_cs`, `firmware_update.log`,
  stalled checkheaps), ASA remote-access VPN abuse, Junos J-Web, IOS XE Zero
  Disco, SMA 100 2025, FortiOS jsconsole bypass and CVE-2022-41328, PAN-OS
  CVE-2026-0300/0257, Ivanti CVE-2026-104935 and NetScaler CVE-2025-6543 and the
  2026 log-poisoning chain. The KEV CVEs with no published indicator are listed
  in `docs/VERIFICATION.md`.
- New read-only collection steps: ASA `show kernel process | include lina_cs`
  and a second checkheaps reading, Junos J-Web jail listing, and five NetScaler
  reads (httpd.conf, rc.netscaler, LogonPoint custom, /flash/nsconfig, /bin/sh).

### Hunts
- New `artifacts/hunts/`: 25 off-box hunts (NetFlow, SIEM, AAA accounting,
  identity, proxies) from CISA/FBI, Cisco, Talos, Mandiant/GTIG, Check Point,
  Fortinet, Volexity, Unit 42 and ASD guidance. Each gives the hypothesis, data,
  method, normal versus suspicious and the quote it rests on. A Hunts library on
  the site.

### Artifacts
- Every catalog artifact now says what it gives you and what normal and
  suspicious look like, and whether the suspicious criterion comes from the
  vendor, a researcher, a government or this toolkit's inference.

### Threat intel
- 358 indicators from 11 publications, parsed from the publishers' own files,
  each with the publisher's role (actor-controlled, compromised third party,
  VPN exit, shared infrastructure, unstated) and a staleness note. Shown
  defanged in each actor and implant, exported as CSV or STIX 2.1.
- A reporting timeline, reporter and motivation splits, an actor-by-platform
  matrix and the share of published addresses that are actually actor-owned.
- New implant record for the FXOS `lina_cs` persistence (`EDGE-IMP-0013`).

## 0.5.0 - 2026-10-22

### Prevention and hardening
- New `artifacts/hardening/`: 83 controls - a 12-control baseline for every
  edge device (CISA BOD 23-02, the 2025 joint edge-device guidance, NCSC-UK's
  forensic-monitoring specification, NSA) and vendor-specific controls for all
  ten platforms, led by keeping management interfaces off the internet.
- Every control states what to do, why (with the CVEs or campaigns the source
  says it blunts, linked into the detections and intel), how in the vendor's
  own syntax - or says the vendor gives none - and its sources with verbatim
  quotes. The validator requires a source on every control and flags low
  confidence.
- Site: a Hardening library (filters for applies-to, category, priority,
  confidence), a sixth "Harden" step on Start, hardening links from platforms
  and response playbooks, and a "Prevent the next one" section in the guide.

## 0.4.2 - 2026-10-22

### Site
- Tabs put the knowledge first - Start, Artifacts, Platforms, Detections,
  Threat intel, Response - with Collection plans, Rules, Coverage and the Guide
  after the divider. Start still links each platform's plan directly.
- Start gains three visuals, each computed from the repository: a volatility
  bar on every platform tile (the share of its artifacts that are live and gone
  at reboot), a five-step triage flow linking to the right tab or guide
  section, and the order-of-volatility band the collector enforces.
- Tabs fit at tablet widths (counts hide below 1120px, the bar fades when it
  scrolls).

## 0.4.1 - 2026-10-22

### Site
- New **Start** landing page for first-time visitors: a platform picker that
  links each device to its collection plan, artifacts, detections and response;
  the first-hour rules; the collect-analyze-respond workflow; and a legend for
  every badge.
- Tabs reordered to follow an investigation (Start, Platforms, Collection
  plans, Artifacts, Detections, Threat intel, Response), with Rules, Coverage
  and the Guide after a divider. The guide is a normal tab, not a floating
  button.
- Coverage leads with computed gaps (no profile, implants with no detection,
  platforms without memory evidence or a confirmed-tier detection, steps that
  are not vendor-documented), then a platform-by-evidence-class detection grid,
  a per-profile verification bar and an artifact grid on one colour ramp. The
  per-pack grid is folded. Count grids no longer reuse the tier colours.
- Investigation guide: contents in the side rail with the current section
  highlighted, linkable sections (`#guide/analysis`), notes for all ten
  platforms (Check Point, Juniper, IOS XE, F5 and SonicWall were missing) with
  links into the libraries, a verdict decision table, a warning callout, and
  verdict and tier names shown as the same badges the libraries use.
- Typography: one sans family and five sizes (was 21-23 font, size and weight
  combinations per view across 11 sizes). Monospace only for literal strings -
  commands, paths, file names, patterns, rules - and code inside prose is
  wrapped inline instead of setting whole sentences in monospace. Artifact
  descriptions are larger and higher-contrast. Font stacks prefer Segoe UI and
  Cascadia Mono on Windows.
- `--check` fails if a platform has no note in the guide or a guide link points
  at a missing section.

## 0.4.0 - 2026-10-22

### Site
- Rebuilt around five filterable libraries - artifacts (new, 78 rows across
  every platform), platforms, detections (68, no longer grouped under packs),
  rules and threat intel - each with a facet rail and live counts, search with
  "N of M shown", a detail drawer with a deep link per record and keyboard
  stepping, and CSV/JSON export of the picked or shown records.
- Filter state is in the URL, so a filtered view can be shared. Old
  `#packs/<id>` links land on the detections library filtered to that pack.
- Coverage matrices are clickable, and a new artifacts-by-platform-and-class
  matrix shows where collection is thin.
- Threat intel opens with clickable summary tiles (coverage gaps, implants that
  survive a reboot); response playbooks are one platform at a time with the
  do-not list first.
- Phone layout: filters fold into one button, rows become cards, the drawer goes
  full screen.
- `tests/test_site.py` drives the page in Chromium (skipped without Playwright).

### Project
- Verification no longer assumes a hardware lab: vendor virtual editions,
  contributed sanitized replay captures and vendor-documented output samples
  (ROADMAP, CONTRIBUTING).

## 0.3.0 - 2026-10-22

### Platforms
- **Juniper Junos** (`EDGE-0008`, profile `junos`, pack 0010): UNC3886 TINYSHELL
  backdoors - masquerading process names, staging files, login-record backups,
  published YARA strings. CLI-only collection; JMRT quick-scan is break-glass
  because it deletes evidence by default.
- **Cisco IOS XE** (`EDGE-0009`, profile `cisco-iosxe`, packs 0011-0012): the
  2023 web UI implant (syslog strings, Talos-named accounts, Cisco's implant
  check) and AA25-239A tradecraft (captures on bootflash, shell trace logs,
  encoded web services requests). New coded check for executable and writable
  IOSd memory with dirty pages, from Cisco's forensic guide.
- **F5 BIG-IP** (`EDGE-0010`, profile `f5-bigip`, packs 0015-0017): c05d5254
  after CVE-2025-53521, CVE-2026-94127 (APM OAuth), and the 2022-2023
  control-plane flaws. New coded check for bursts of invalid-token UserInfo
  failures, using F5's rule of 10 or more in one log (especially from one address).
- **Check Point** (`EDGE-0007`): now has a profile, and packs 0013-0014 cover
  CVE-2026-93616, CVE-2026-16232, CVE-2026-85102 and CVE-2026-50751 using
  Check Point's published indicators.

### Intel and response
- Actors: UNC3886 now linked to Juniper; new AA25-239A profile that keeps the
  agencies' refusal to adopt a vendor name and records the Talos disagreement.
- Implants: UNC3886 Junos TINYSHELL, IOS XE web UI implant, F5 c05d5254.
- Response playbooks for Juniper, IOS XE and F5; Check Point rewritten for the
  2026 flaws with per-CVE fixes, interim mitigations and the sk182336 rotation list.

### Engine
- Coded checks report "not evaluated" when they parse nothing, so an error
  message can never pass as a clean device (applied to the ASA check as well).
- Profile steps can declare `var_examples` so the load-time guard probes with
  realistic values (an IOS XE `bootflash:` path rather than `/placeholder`).
- Rule directories may now be numbered past 09.
- Rotated `.gz` logs are now decompressed before matching. Previously every
  rotated log was searched as compressed bytes and silently came back no-hit.

### Verification round 2 (same day)
- F5 audit detection matched `cmd=` instead of the real `cmd_data=` field.
- Check Point `cpinfo` now runs with `-D -d` so it never uploads to the vendor
  or self-updates; the vpnd detection uses the real blocked-traversal message.
- Junos: listing patterns tolerate `file list` type markers (they matched
  nothing before); JMRT integrity-check is opt-in because it writes a test file;
  process-name detection lowered to possible; new hijacked-cat, payload-file and
  syslog.conf0 detections; /mfs/var/etc listing.
- IOS XE: image hashing follows packages.conf to each .pkg; the Catalyst switch
  form of the IOSd memory map is collected and read; the Sigma web services rule
  accepts mixed encodings.
- Every correction is in `docs/VERIFICATION.md`.

## 0.2.0 - 2026-10-22

### Verification
- Every claim checked against primary sources in three independent passes. Full
  audit trail with the basis for each change in `docs/VERIFICATION.md`.
- **Fixed a silent false negative:** the ASA `show memory region` parser expected
  a layout no device prints, so it reported "no hit" on a compromised ASA. It
  now parses the real `/proc/maps` format and is pinned by a regression test.
- Corrected attribution (UTA0576 is assessed criminal, not espionage), the
  Ivanti syslog-blocking attribution (operator commands, not SPAWN malware),
  and fifteen further facts. Secondary sources replaced with primaries.

### Artifacts
- Every platform entry now carries per-artifact rows: locator, what it proves,
  evidence class, volatility and retention, forensic value, evidence type, the
  step that collects it, and confidence.

### Threat intelligence and attribution
- `artifacts/intel/actors/` - 6 actor profiles. Attribution is reported, never
  computed: each carries our link confidence and the reporter's own words.
- `artifacts/intel/implants/` - 9 implant entries with what survives reboot,
  upgrade and factory reset. An implant with no detection must state its gap.

### Containment and recovery
- `artifacts/response/` - 7 playbooks ordered preserve, contain, rotate
  credentials, eradicate, recover, verify, each with a "do not" list.

### Site
- New Threat intel and Response tabs; artifact tables on every platform card.
- Validator cross-checks actors, implants, response playbooks and every
  `collected_by` reference.

## 0.1.0 - 2026-10-22

First cut.

### Engine (`edgetriage`)
- `plan`, `collect`, `ingest`, `analyze`, `timeline`, `brief` subcommands.
- Order-of-volatility tiers (V0-V3, P1-P7, B, X) enforced by the engine.
- Read-only guard enforced at profile load and again after `--var` substitution.
- Impact gating: vendor bundles behind `--allow-bundle`, break-glass behind
  `--break-glass` plus typed confirmation, always last.
- SSH transport for restricted CLIs (pager handling, echo/ANSI stripping,
  host-key pinning or known_hosts, no trust-on-first-use); replay transport.
- Chain-of-custody manifest with tool hash, profile hash, per-artifact SHA-256,
  preflight answers and a previous-manifest hash on every rewrite.
- Hostile-archive extraction: regular files only, refusals recorded.
- Analyzer with `hit` / `no-hit` / `not-evaluated`, cross-class corroboration
  scoring, evidence-gap reporting, Markdown report.

### Content
- Profiles: `panos`, `fortios`, `netscaler`, `cisco-asa`, `ivanti-ics`.
- Catalog: EDGE-0001 to EDGE-0007.
- Packs: EDGE-PACK-0001 to EDGE-PACK-0009 (28 detections).
- 7 Sigma rules, 2 YARA files (5 rules).

### Security hardening (independent review, same day)
- Allow rules are full-command grammars matched with `fullmatch`; the old
  prefix rules let a newline-separated second command through.
- Control characters refused in every command, `session_setup` line and `--var`
  value; `--var` values limited to path and host characters for every impact.
- NetScaler `shell find` restricted to a fixed option grammar (quote and
  backslash tricks admitted `-delete` and `-exec`); `show` limited to four commands.
- Transport tests only the last line for prompt and pager, and requires a quiet
  period after a prompt, so device output cannot end a capture or delete text.
- Fetch refuses non-plain paths from device listings, pseudo-filesystems,
  non-regular files and files over 512 MiB.
- Ingest validates labels; extraction refuses duplicate and clashing members and
  drive-qualified names, and records an aborted extraction instead of crashing.

### Not yet verified
- No profile has been run against a real device. See `docs/ROADMAP.md`.
