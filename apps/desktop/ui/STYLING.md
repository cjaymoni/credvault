# Styling the klavyn UI

Read this before changing anything in `ui/*.css`. It is short because the
system is small: two stylesheets, no build step, no framework, and one idea —
**cascade layers decide what wins.**

## What is here

- `styles.css` — tokens, base, components, and the two layers that exist to
  win arguments (`context`, `invariants`).
- `platform.css` — everything that differs per platform, keyed off
  `data-platform` on `<html>` (`macos`, `windows`, `linux`, `ios`, `android`).

`index.html` links both directly. There is no bundler, no PostCSS, no
`package.json`. What you edit is what ships, so a reload shows your change.

## The layer order

Declared once at the top of `styles.css`:

```css
@layer tokens, base, components, context, platform, invariants;
```

A later layer beats an earlier one **whatever the selectors say**. A one-class
rule in `context` beats a three-class rule in `components`. This is the whole
point: you never need to inflate a selector to win.

| Layer | Holds | Example |
| --- | --- | --- |
| `tokens` | custom properties only: the palettes, type scale, spacing | `:root`, `:root[data-platform="ios"][data-theme="dark"]` |
| `base` | element selectors, resets, focus rings, global utilities | `*`, `body`, `:focus-visible`, `.hidden` |
| `components` | everything a screen is built from, plus its responsive blocks | `.btn`, `.field`, `.card`, the phone layout |
| `context` | a component re-dressed for where it sits | `.label-row > label`, `.custom-field .cf-hide` |
| `platform` | the whole of `platform.css` | `[data-platform="macos"] .form-actions` |
| `invariants` | meaning a platform must not be able to erase | `.btn.danger.solid` |

## Choosing a layer

Work down this list and stop at the first that fits.

1. **Is it a colour, size or spacing value that varies by platform?** Set a
   token in `tokens` and have the component read it. Of the 331 rules in
   `platform.css`, 193 set nothing but values — each one is a token that has
   not been named yet. Prefer the token.
2. **Does it change what a thing *is* — display, order, grid, position?**
   That is `platform` if it varies per platform, `components` otherwise.
3. **Is it the same component dressed differently because of where it sits?**
   That is `context`. A label above a field has a bottom margin; the same
   label beside a checkbox must not. Put the exception here, with the plain
   selector, and let the layer win.
4. **Would losing it change what the interface means, not how it looks?**
   That is `invariants`, and it is nearly always the wrong answer. There is
   one member: the red of the button that confirms a delete. A platform rule
   that paints every button the window's surface colour would otherwise make
   a destructive action look ordinary.

Anything else belongs in `components`.

## Rules that are enforced, not just asked for

`ui-tests/layers.test.js` and `ui-tests/tokens.test.js` run with
`node --test apps/desktop/ui-tests/`. They will fail you for:

- **A rule outside any layer.** Unlayered rules beat every layered one, so a
  single stray rule reinstates the problem layers were adopted to solve. Every
  top-level block in both files must be `@layer <name> { … }`.
- **A layer that is used but not declared.** Its position would then depend on
  load order, which is the thing being designed away.
- **A nested rule, or an at-rule the reader does not know.** The test reader
  is deliberately narrow: block at-rules only, no nesting. Native CSS nesting
  needs Safari 17.2 / Chrome 120, well above this app's floor, and some Linux
  WebKitGTK builds are older still. Do not use it.
- **A dark palette that drifts.** Every one is written twice — once under
  `@media (prefers-color-scheme: dark)`, once under `[data-theme="dark"]` —
  and the two copies must resolve to the same tokens.

## Traps worth knowing

- **`.field label` has a bottom margin** (6px, 8px on a phone) to separate a
  label from its field. Used as a row item it pushes the label off centre,
  because flex and grid centring both count margins. The fix is a `context`
  rule, not a more specific selector. This has caused two visible bugs.
- **Optical alignment is not box centring.** A line box is taller than the
  word in it, so an icon centred against the box reads low — by different
  amounts at different font sizes, which is why a fixed `translateY` nudge
  cannot settle it. Put the icon inline with `vertical-align: middle` and it
  sits on the text's own x-height at any size.
- **The CSP allows no `data:` URLs** (`default-src 'self'; style-src 'self'
  'unsafe-inline'`). Carets and ticks are drawn with borders and transforms,
  or left as the platform's own control. Do not reach for an inline SVG
  background image.
- **`env(safe-area-inset-*)` is zero in Android's WebView**, even edge to
  edge: a navigation bar is a window inset and never reaches CSS. Read the
  `--safe-*` properties instead; `MainActivity.kt` fills them in.

## Changing something that must not change

The stylesheets are shared by five platforms and two themes, so "it looks
right here" proves little. For a refactor meant to be invisible, dump
`getComputedStyle` for every element across every platform, theme and screen
before and after, and diff. The layer migration was verified that way:
533,680 property values across 40 combinations, zero differences.
