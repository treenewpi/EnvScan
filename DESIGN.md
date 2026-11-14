# EnvScan visual design (RootBeer style)

## Reference

RootBeer's result screen: one verdict on top, a list of pass/fail checks below it, each with a
green tick or a red cross, and tapping an item explains what it looks at and why it matched.
EnvScan keeps that information structure but splits the results into "risks" and "other
checks", with risks always first.

## Four-line brief

- Theme: a health check for a device. The first thing you see is **abnormal + how many items
  need attention + a red cross**.
- Layout: verdict card (status icon + headline + ratio bar + counters) → action → risk list →
  other checks.
- Colour: `#F5F7FA` canvas / `#FFFFFF` list / `#111827` text / `#6B7280` secondary / `#DC2626`
  risk / `#D97706` warning / `#16A34A` pass.
- Explicitly avoided: dark neon, full-screen monospace stacks, coloured dots, uniform card grids.

## Rules

- Risk first: FAIL + WARN form the first group with FAIL on top; PASS / NA form the second.
- One line says one thing: status icon + title + a single line on how it is checked; details
  stay out of the list.
- Tapping any item opens a dialog with three fixed sections: **how it is checked / why / raw
  evidence**.
- The "how" text comes from `CheckGuide`: key items describe exactly what is read, the rest use
  a per-group description; the "why" combines this run's status with the first evidence line.
- Icon semantics are fixed: red cross = risk, amber exclamation = warning, green tick = pass,
  grey question mark = undecidable.
- Animation is limited to the progress bar while scanning; no per-row entrance animation.

## Screens

1. **Empty**: shield icon + a large `108` + one sentence + start scan.
2. **Report**: verdict card → scan again / 108 items → "Risks" list → "Other checks" list.
3. **Detail**: status + title + group/id + how it is checked + why + raw evidence + copy.
