---
name: HAProxy Studio
description: A light workspace for HAProxy administration.
colors:
  background: "#f5f6f7"
  surface: "#ffffff"
  text: "#202726"
  muted: "#596561"
  border: "#dce2df"
  rail: "#192522"
  accent: "#17664e"
  accent-hover: "#104c3a"
  danger: "#a62d31"
  soft: "#e9f3ed"
  focus: "#37836b"
typography:
  headline:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "18px"
    fontWeight: 700
    lineHeight: 1.4
  body:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  control: "8px"
  panel: "12px"
  dialog: "16px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  xxl: "32px"
  xxxl: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "12px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
  badge:
    rounded: "6px"
    padding: "5px 10px"
---

# Design System: HAProxy Studio

## Overview

Creative North Star: **Operate**.

A light administrative workspace with graphite navigation, forest-green actions, compact route tables and readable configuration. Status comes from actual installation data. No approved raster comp was used; the user delegated direction and implementation.

Key Characteristics:

- Light workspace and graphite navigation.
- Restrained green actions and explicit status text.
- Compact tables and readable configuration.
- Responsive navigation and account controls.

## Colors

Primary green identifies actions, links and the login wordmark. Pale background, white surfaces, dark text and quiet borders form the neutral hierarchy. Status includes text alongside green, adverse red or neutral tones. Focus uses the distinct green outline token.

## Typography

Manrope is served locally. The bundled face declares weight 400; heavier headings and controls use browser font-weight synthesis. Mobile page headings use 26px. Prose measure is 72ch. Monospace serves config, addresses and technical values. Metric values remain Manrope with tabular numerals: 30px on desktop, 26px at the intermediate breakpoint, 28px on mobile.

## Layout

Desktop rail: 232px; main inset: 40px. At <=1100px the rail is 208px, main inset is 32px vertically and 24px horizontally, and summary columns stack. At <=767px the rail becomes a header with a disclosure: section navigation and account controls, including logout, expand together. Main inset is 28px vertically and 16px horizontally; metrics form two columns. At >=1600px main content is centered within 1480px. Focusable table wrappers scroll locally; mobile tables retain 640px minimum width. Panels use 24px insets, reduced to 20px on mobile.

## Elevation & Depth

Flat white surfaces, borders and tonal separation; no box shadows. The native configuration-review dialog uses a translucent dark backdrop to protect the pending decision.

## Shapes

Controls use 8px corners, panels 12px, login and review surfaces 16px. Small badges use 6px corners. Fine table dividers maintain scanability.

## Components

Exchange path rows use native details for progressive disclosure; source pools and probes are edited inside each row. Shared TLS ports expose SNI domains and an explicit no-SNI fallback checkbox. Multi-domain certificates use a labelled native multiple select. Existing typography, focus and colors remain authoritative.

The service wizard uses three stages: service type, addresses/security, and review. Fields stack on mobile, advanced options use native details, and final confirmation shows plain-language changes before the optional technical diff. Existing operator controls and colors are preserved. New wizard section titles use 22px; progress labels use 13px on desktop and 12px on mobile.

Buttons have 44px minimum height and weight 600; compact table actions are 36px. Secondary hover and active states use pale green-gray, primary hover darkens green. Disabled controls reduce opacity and use a default cursor. Inputs and editor use white surfaces and quiet borders. The monospace editor preserves whitespace, scrolls internally and resizes vertically; its font is 16px on mobile. Navigation marks the current section with aria-current. Native dialog apply remains disabled until a valid draft exists. Missing metrics use an em dash, never a fabricated healthy zero. Keyboard focus is a 3px outline with 3px offset. Control feedback lasts 160ms; reduced-motion preference removes transitions. Selection and caret use the green palette.

## Do's and Don'ts

### Do:

- Use real data and explicit unavailable states.
- Keep focus, table scrolling and mobile logout accessible.

### Don't:

- Do not fabricate charts or healthy zero values.
- Do not introduce promotional hero content.

## Compact operator workspace

The default compact density reduces list, panel and form spacing while keeping 40–44px controls, visible focus and 16px mobile inputs. The header density toggle persists in local browser storage and restores the comfortable layout. Desktop navigation stays visible within a scrollable sticky rail. Long operator collections use local search, explicit counts and 8/20/50/all paging; no data is removed. Routes use their existing global search, which expands matching infrastructure disclosures. Technical frontend entries and certificate composition are collapsed initially. Exchange summaries distinguish external ports, internal ports and SNI/STARTTLS.
