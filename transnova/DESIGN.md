---
name: TransNova SOC
description: The defender's console for a three-honeypot lab; evidence first, interpretation beside it.
colors:
  cabinet-green: "#24413a"
  cabinet-green-raised: "#2d4f46"
  rail-ink: "#e4ece8"
  rail-muted: "#b3c6bd"
  stone-ground: "#eceae4"
  label-stock: "#fbfaf6"
  label-sunk: "#f4f2ec"
  hairline: "#cfccc2"
  hairline-soft: "#e2dfd6"
  ink: "#1d2321"
  ink-secondary: "#47524d"
  ink-muted: "#5f6a65"
  brass: "#a8823a"
  brass-ink: "#74581f"
  brass-wash: "#f3ead6"
  focus: "#7d5f22"
  curator-red: "#9c3b2a"
  curator-red-wash: "#f6e3de"
  amber-ink: "#6e5112"
  amber-wash: "#f3e8cd"
  ok-ink: "#2a5f45"
  ok-wash: "#dfece4"
  info-ink: "#24506f"
  info-wash: "#e2ebf1"
  series-web: "#2f6f9f"
  series-database: "#b07a1e"
  series-ssh: "#7d4f9e"
  series-soc: "#2e8a5c"
typography:
  page-title:
    fontFamily: "Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  panel-title:
    fontFamily: "Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 700
    lineHeight: 1.3
  body:
    fontFamily: "Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
  table:
    fontFamily: "Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
  small:
    fontFamily: "Atkinson Hyperlegible, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
  data:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
rounded:
  sm: "6px"
  md: "8px"
  pill: "999px"
spacing:
  s1: "4px"
  s2: "8px"
  s3: "12px"
  s4: "16px"
  s5: "20px"
  s6: "24px"
  s8: "32px"
  s10: "40px"
components:
  button-primary:
    backgroundColor: "{colors.cabinet-green}"
    textColor: "#ffffff"
    rounded: "{rounded.sm}"
    padding: "7px 14px"
  button-secondary:
    backgroundColor: "#ffffff"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "7px 14px"
  panel:
    backgroundColor: "{colors.label-stock}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "20px"
  slip-rule:
    backgroundColor: "#ffffff"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "12px 16px"
  slip-analyst:
    backgroundColor: "{colors.brass-wash}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "12px 16px"
  slip-ai:
    backgroundColor: "{colors.label-sunk}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: "12px 16px"
  badge-critical:
    backgroundColor: "{colors.curator-red}"
    textColor: "#ffffff"
    rounded: "{rounded.pill}"
    padding: "1px 8px"
  nav-item-active:
    backgroundColor: "{colors.label-stock}"
    textColor: "{colors.cabinet-green}"
    rounded: "{rounded.sm}"
    padding: "9px 12px"
---

# Design System: TransNova SOC

## Overview

**Creative North Star: "The Collection Cabinet"**

The console works like a natural-history collection. Every honeypot interaction is a catalogued specimen: an immutable event with its ID, time, place and raw evidence. Every judgement about it is a *determination slip* laid beside the specimen, never written over it. A rule's conclusion, an analyst's classification and an AI interpretation are three kinds of slip, styled so a reader can tell them apart at a glance. This is how the interface keeps observed fact apart from inference.

The world is calm and warm without being cream-and-serif. A cabinet-green rail holds navigation. Panels are label stock on a pale stone ground, divided by one hairline system. Colour is earned: brass marks what is new or selected, curator red appears only for high and critical severity, and a single failed login looks like the ordinary event it is. Built for an analyst at a desk and a projector in front of judges, so legibility outranks density.

**Key Characteristics:**
- Determination slips (rule, analyst, AI) as the signature component
- One hairline border system; no shadows doing structural work
- State told in sentences ("The collector has stored 129 events"), not KPI tiles
- Tabular mono figures for every ID, time and count; prose in a hyperlegible sans
- Honest empty, stale and unavailable states everywhere

## Colors

A restrained palette: a committed green shell, tinted neutrals, and state colours that each have one job.

### Primary
- **Cabinet Green** (#24413a): the rail, primary buttons and the active-tab underline. It carries the brand at shell scale, never as small accent dots.

### Secondary
- **Brass** (#a8823a): new-since-last-visit marks and selected states. Brass Ink (#74581f) and Brass Wash (#f3ead6) style analyst slips and classification badges.

### Neutral
- **Stone Ground** (#eceae4): the page field.
- **Label Stock** (#fbfaf6): panels. Label Sunk (#f4f2ec) is for evidence blocks and hovered rows.
- **Hairline** (#cfccc2) and **Hairline Soft** (#e2dfd6): every border and table rule.
- **Ink** (#1d2321), **Ink Secondary** (#47524d) and **Ink Muted** (#5f6a65): text, all at 4.5:1 or better on label stock.

### Named Rules
**The Earned Red Rule.** Curator red (#9c3b2a) marks only high and critical severity and the alert states *confirmed malicious* and *error*. Being in an alert, matching a rule or failing a login is never red. Membership in an alert uses amber; a rule match uses neutral grey.

**The Series Rule.** Decoy identity in charts and tags uses the validated categorical set in fixed order: web #2f6f9f, database #b07a1e, SSH #7d4f9e, console #2e8a5c. It passes CVD separation at ΔE ≥ 14 on label stock. Text never takes a series colour.

## Typography

**Body Font:** Atkinson Hyperlegible (self-hosted, 400 and 700), chosen for projector legibility.
**Data Font:** JetBrains Mono (self-hosted, 400), with tabular figures.

**Character:** a single humanist workhorse sans for every label, heading and sentence, with mono reserved for what is data: IDs, timestamps, addresses, commands, paths and counts.

### Hierarchy
- **Page title** (700, 28px, -0.015em): one per page.
- **Panel title** (700, 17px): sentence case, never uppercase-tracked.
- **Body** (400, 15px/1.5): ledes capped at 72ch.
- **Table** (400, 14px): table cells.
- **Small** (400, 13px): column headers, slip metadata, captions.
- **Data** (JetBrains Mono 400, 12–13px): tabular figures.

### Named Rules
**The Mono-Means-Data Rule.** Monospace marks values that came from a machine, such as an ID, a timestamp, an address, a command or a path. It is never decoration and never sets prose.

## Layout

A 232px sticky rail and a fluid main column (max 1440px, 40px gutters). Pages stack panels on a 24px rhythm. Detail pages use a two-column grid: evidence and investigation on the left, a 400px summary, mapping and disposition column on the right. Below 1180px it becomes one column. Below 900px the rail turns into a top bar with horizontally scrolling navigation. Wide tables scroll inside their panel, so the page never scrolls sideways.

## Elevation & Depth

Flat by default. Structure comes from the hairline border on label-stock panels against stone ground. The only shadows are a 2px panel-coloured ring on timeline dots and the soft shadow under the chart tooltip (`0 6px 18px rgba(29,35,33,0.18)`).

### Named Rules
**The One Hairline Rule.** Every container declares its edge with a 1px hairline. Containers never pair a border with a wide soft shadow, never use side stripes thicker than 1px, and never nest a card in a card.

## Shapes

Panels round at 8px, controls and slips at 6px, badges and chips are full pills. Session duration bars are 6px tall with 3px ends, and their length is the session's real duration relative to the longest one shown.

## Components

### Buttons
- **Primary:** cabinet green, white text, 6px radius, 7px 14px padding. Hover deepens to #1b3530.
- **Secondary:** white on a hairline border. Hover moves to label sunk with a darker border.
- **Quiet:** borderless, for "Add note only" and similar low-weight actions. Disabled buttons sit at 55% opacity with a not-allowed cursor.

### Chips and Badges
Pills at 12.5px. Severity: critical is red with white text, high is a red wash, medium is amber, low is neutral. Alert status, detection state (observed / rule matched / in an alert) and sensor health each have their own wash. Every badge carries its meaning in words, never colour alone.

### Cards / Containers
**Panels** are label stock with a hairline border, 8px radius and 20px padding. A panel's title row may hold a right-aligned aside, such as the span guide or a link.

### Inputs / Fields
White field, hairline border, 6px radius. The label sits above in 13px secondary ink. Hover darkens the border, and focus shows a 2px brass-ink outline offset by 2px.

### Navigation
Rail links are 15px with a 17px lucide icon and a tabular count. The active link inverts to label stock with cabinet-green text. The rail footer shows the live-update state as a dot plus words, then the user and Sign out.

### Determination Slip (signature)
A white card on a hairline border. The top row holds the rule ID and source in mono with a severity badge. Then comes the title, then a dashed hairline and the determination line (*det. rule match · confidence high · 4 events*). Variants: **rule** (white), **analyst** (brass wash, signed with actor and time), **AI** (label sunk, dashed border, labelled with the model and "not verified"). Slips stack; they never replace each other.

### Span Guide
The table head names the first and last timestamp in view (`03:08:39 – 03:16:28`), so the reader always knows which span they are reading.

## Do's and Don'ts

### Do:
- **Do** show raw evidence as preformatted text and never as HTML; attacker strings render inert.
- **Do** write state as sentences and empty states that say what will make data appear.
- **Do** mark items new since the last visit with a brass dot and keep rows in place between refreshes.
- **Do** label AI output as interpretation and keep it in its own slip.

### Don't:
- **Don't** use red for anything below high severity, including failed logins, rule matches and membership in an alert.
- **Don't** build KPI-tile rows, donut charts or neon threat maps; the overview answers four questions in sentences.
- **Don't** put a kicker or eyebrow above a heading, or uppercase-track section titles.
- **Don't** fill an empty or unavailable view with sample data or a remembered value.
- **Don't** use monospace for prose or as a "technical" costume.
