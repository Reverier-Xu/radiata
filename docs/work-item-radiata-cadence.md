# Work Item: `radiata-cadence` — a cron-replacement schedule-pattern syntax

Status: approved design, not yet started. Decided in the pre-0.1.0 design
discussions of 2026-11-07/08 (companion documents:
`docs/code-quality-audit.md`, the trigger-framework design sections of the
task/trigger discussion).

## Motivation

The planned trigger framework (declarative triggers on the unified row
model) needs a calendar expression language. Surveyed prior art — Temporal
Schedules, systemd `OnCalendar`, Kubernetes CronJob, RFC 5545 RRULE —
converges on: structured second-precision field selectors, spec/policy
separation, IANA or fixed-offset timezones with literal DST matching, and
catchup/overlap policies. Existing concrete syntaxes are either minute-only
with a legacy grammar (cron), or embedded in heavyweight systems.

The decided approach is a **self-defined grammar**: RFC 3339 with
set-valued fields. Every engineer already knows the shape; it is second-
precision by construction; it validates, canonicalizes, and golden-tests
cleanly; and it needs no timezone database (fixed offsets and device-local
evaluation cover the decided semantics).

The grammar is general-purpose and owns nothing of the cluster: it is
extracted as an independent crate so its versioning, docs, and publishing
identity do not ride on radiata's release cadence.

## Name

`radiata-cadence` (workspace member, `publish = false` until extracted).
"Cadence" is already a runtime term of art in this crate (anti-entropy
cadence, quiet-detection cadence), so the syntax library and the runtime
share one vocabulary.

## Grammar (v1 draft, to be frozen by golden tests)

```
pattern  := field "-" field "-" field "T" field ":" field ":" field offset?
field    := "{" set "}" | literal            ; exactly two forms per field
set      := element ("," element)*          ; non-empty, mixed forms allowed
element  := "*" | dd | dd "-" dd            ; "*" = full domain; ranges closed on both ends
literal  := dd | dddd                       ; a bare single numeric value
offset   := "Z" | ("+"|"-") dd ":" dd       ; "Z" is sugar for "+00:00"
```

A field is either a **braced set** or a **bare single numeric literal**
(`00`, `2026`) — nothing else. Bare `*`, bare ranges, and bare
enumerations are syntax errors: reserving the unbraced form for single
literals keeps `-` unambiguous between the date separator and the range
syntax (the decision that motivated the brace rule).

- Fields: second/minute 0-59, hour 0-23, day 1-31, month 1-12, year 0000-9999.
  Two-digit zero-padded spellings throughout (four-digit year); ranges are
  `dd "-" dd`, inclusive; mixed sets like `{3,9-12}` are allowed; duplicate
  set elements are rejected.
- The skeleton is fixed (six fields, `T`, separators); no whitespace;
  anything else fails validation.
- **Matching rule (the whole semantics):** a wall-clock second (in the
  reference frame below) fires iff each field's value is a member of its
  set. One rule, no special cases.
- **Timezone / reference frame:** a trailing fixed offset anchors evaluation
  to that civil frame, independent of the device; an omitted offset evaluates
  in the device's local wall clock. Placeholders inside the offset are
  forbidden by construction.
- **DST: literal matching, deliberately.** Nonexistent local times do not
  fire; duplicated local times fire twice. Predictability over cleverness —
  same stance as Temporal and systemd.
- Calendar-natural consequences that fall out for free: `{2}-{29}` fires
  only in leap years; `{2}-{30}` never fires.
- Granularity is seconds, matching the crate-wide second-granularity
  discipline.

### Deliberate non-features (v1)

- **No `every`/interval kind, no steps.** Field-set matching is
  field-decomposable, so cross-field periods ("every 90 minutes") are not
  expressible — but no mainstream calendar cron expresses them either
  (Vixie/ISC, Quartz, and systemd `OnCalendar` steps are all field-local);
  cross-field periodicity belongs to the monotonic-timer family
  (`OnUnitActiveSec`, Temporal `IntervalSpec`). If radiata ever needs
  intervals, they land in the trigger-declaration layer as a second spec
  kind, never in this grammar.
- **No cron-string compatibility.** A replacement does not carry the
  replaced grammar.
- **No jitter.** Phase decorrelation is a backoff/retry concern, not a
  scheduling concern; triggers fire exactly.

## Scope boundary

The crate owns: grammar (parse/validate/canonical form), compiled per-field
set masks, match evaluation, next-fire ordered search, golden + fuzz
corpora. Estimated ~1-2k lines, pure `std`, zero dependencies.

The crate does **not** own: wall-clock reading, timezone-database access
(the caller resolves the reference frame and supplies field values —
device-local resolution is radiata's job via its `WallClock` seam), timers,
triggers, or task semantics.

## Integration

- Wire format: the canonical form rides the unified row model's
  trigger declarations (node-local, not replicated) once the unification
  roadmap lands the trigger framework (Phase C/D in the audit follow-up).
- Policy fields (catchup = coalesce-to-one, overlap = skip) live on the
  trigger declaration, outside this crate — spec/policy separation per the
  surveyed consensus.
- Observability (recent/next fires, missed count) is the controller's
  surface, not the grammar's.

## Acceptance criteria

1. Grammar frozen by golden tests: canonical forms, reject cases (malformed
   skeletons, duplicate elements, out-of-domain values), round-trips.
2. Parser fuzz target with a structure-aware corpus; no panics, fail-closed
   on every invalid input.
3. Next-fire search proven against a brute-force oracle over dense sample
   spaces, including DST-gap/duplicate and leap-day edges.
4. All repository quality gates green for the new workspace member
   (`taplo`, nightly `rustfmt`, `check`, `clippy -D warnings`, `test`).

## Time-library interop (delivered 2026-11-08, post-merge addendum)

Three optional features bridge caller-side time libraries; all default
off, the core stays dependency-free and clock-blind:

- `std-time`: `SystemTime` <-> `FieldValues` for the `Utc` and
  fixed-offset frames. Sub-second readings floor toward negative
  infinity. The device-local frame is rejected — `std` has no timezone
  database.
- `chrono` (dep `chrono` 0.4, no default features): `TryFrom` any
  `DateTime<Tz>` into `FieldValues` (local civil reading), and
  `FieldValues::to_chrono_fixed` back into `DateTime<FixedOffset>`.
- `jiff` (dep `jiff` 0.2, no default features): `TryFrom` for
  `jiff::Timestamp` / `&jiff::Zoned` / `jiff::civil::DateTime`, and
  `FieldValues::to_jiff_timestamp` / `to_jiff_civil` back.

The device-local frame is resolvable only through `chrono`/`jiff` (their
timezone types own the tz database); cadence deliberately never resolves
local time itself. Errors surface as the shared `TimeInteropError`
(`LocalFrameUnsupported` / `OutOfRange`).

### Project time-library survey (decision record)

- radiata core reads wall clock exclusively through `src/time.rs`
  (`SystemTime` seam, unix seconds/millis scales); tokio's `time` feature
  is the async runtime timer, not a date-time library.
- Dependency tree contains `time` v0.3 only transitively (rcgen -> yasna,
  X.509 timestamp encoding) — an implementation detail of cert issuance,
  not used by, or exposed to, radiata logic. No chrono/jiff/iana-tz
  anywhere. No mixing risk: one clock authority plus the documented
  receipt wire-codec exception.
- Migration to jiff for radiata core is **not warranted**: core semantics
  need only unix-second/millis arithmetic and ordering (liveness,
  LWW tuples); there is no civil-calendar or timezone need, and wall-clock
  reliability is an operator obligation by standing decision. jiff's
  timezone correctness matters only for `Offset::Local` resolution, which
  cadence assigns to the caller's library of choice — hence opt-in
  features for both chrono and jiff so downstream users match whichever
  already sits in their dependency tree.
