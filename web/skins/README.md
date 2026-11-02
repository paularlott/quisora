# Skins

A skin replaces the look of the UI without touching templates or components. Without one the UI has its own liquid
glass look. Choose one with `ui.skin` (`--skin`):

```toml
[ui]
skin = "corporate"                 # a built-in skin (a folder here, compiled into the binary)
# skin = "/etc/quisora/skins/acme" # or the path of a skin folder (./acme: relative to the working directory)
```

## Built-in skins

| Skin | |
| --- | --- |
| `corporate` | Restrained: opaque surfaces with hairline borders, one navy accent, square-ish corners, a solid header. |
| `modern` | Crisp: zinc neutrals going near-black in the dark theme, a teal-to-cyan accent, soft corners, a translucent header, a faint glow and dot grid behind the page. |

Neither ships a logo: set `ui.logo_light` / `ui.logo_dark`, or copy one into a skin folder of your own.

## What a skin holds

| File | |
| --- | --- |
| `skin.css` | Required. Loaded after the built-in stylesheet, served from `/branding/skin.css`. |
| `logo-light.svg` or `.png` | Optional. The logo, used unless `ui.logo_light` is set. |
| `logo-dark.svg` or `.png` | Optional. The dark-theme logo (default: `logo-light`), used unless `ui.logo_dark` or `ui.logo_light` is set. |

A value with a `/` in it is a folder: absolute, or relative to the working directory the server starts in. A bare name
(`acme`) is always a built-in skin, so write a folder in the working directory as `./acme`. The folder's name is the
skin's name: lowercase letters, digits and dashes. The files are read once at start-up, so restart the server after
changing them.

Use fixed colours in logos. A logo is shown as an `<img>`, where `prefers-color-scheme` follows the operating system
rather than the theme the user picked, so the light and dark variants are separate files.

## Writing `skin.css`

The pages set `data-skin="<name>"` on `<html>`, with `data-theme="light|dark"` and `data-layout`: `auth` on the
sign-in, consent and other end-user pages, `app` on the console and account pages. A skin sets the design tokens of
`web/src/css/tokens.css` under `:root[data-skin="<name>"]`. That selector is as specific as the built-in dark theme's
and comes later, so it wins:

```css
:root[data-skin="acme"] {
  --page-bg: light-dark(#f7f7f5, #111110);
  --accent-solid: #0f766e;
  --glass-bg: light-dark(#ffffff, #1b1b1a);
  /* ... */
}
:root[data-skin="acme"][data-layout="auth"] { --accent-solid: #134e4a; }
```

- Use `light-dark(light, dark)` for colours that differ between the themes. The theme sets `color-scheme` on `<html>`,
  so one declaration covers light, dark and visitors without JavaScript (who get their OS preference). It works only
  for colours: set non-colour tokens once, or under `:root[data-skin="<name>"][data-theme="dark"]`.
- Start from a copy of `corporate/skin.css` or `modern/skin.css`: each defines a small palette (`--sk-*`) and maps it
  onto every token once.
- Every colour, shadow, radius and surface treatment the components use is a token: buttons, switches, the avatar,
  the current navigation link and so on. Prefer tokens to restyling components. A skin may add plain rules too, as
  the built-in skins do to replace the aurora backdrop.
- Plain CSS only: the file is served as is, so there is no Tailwind (`@apply`, utilities) and no `@import`. Load
  nothing from other origins (fonts, images): the server works on networks without internet access, and the
  Content-Security-Policy would block them anyway.
- The reduced-transparency and more-contrast preferences still apply under a skin (they are `!important` in
  tokens.css).
- Keep WCAG 2.2 AA: text 4.5:1 and controls 3:1 against the surfaces they sit on, in both themes. The accessibility
  audit runs against a skin with `SKIN=<name> npx playwright test a11y` in `web/` (a built-in name, or a folder's absolute path).

## Organization branding

An organization may have a logo of its own (and a dark-theme one) and a primary colour, which an administrator of the
organization sets on its page in the console or with `PATCH /api/orgs/{org}/branding`. Its sign-in pages
(`/o/<org>/…`) and the console of its users then show:

- its logo, and its display name in place of `ui.site_name` (page titles and header; the sign-in card drops the site
  name under the logo, since its heading already reads "Sign in to <org>"),
- its colour for buttons, links and focus rings.

Without a logo the server's is shown (`ui.logo_light` / `ui.logo_dark`, or the skin's) with the server's site name;
without a colour the skin's accent stays. The skin still decides everything else, so the organization's logo and colour
sit inside the skin's look. Organization branding is not a place for a stylesheet: only the logo and the colour can be set.

- **Colour.** `#rrggbb`, dark enough that white text on it has a contrast of at least 4.5:1 (WCAG 2.2 AA), since
  buttons are filled with it under white text. Link text and focus rings use it darkened (light theme) or lightened
  (dark theme) until it reads at 4.5:1 on the page.
- **Logos.** A `data:` URI (`data:image/png;base64,…`) of a PNG, JPEG, WebP or SVG image, at most 256 KB decoded each,
  whose content must be the type the URI says. A dark logo needs a light one, and removing the light one removes the
  dark one too. They are stored in Quisora's own database (the `organization_logos` table, replicated and backed up
  like other records) and served by Quisora at `/o/<org>/branding/logo-light` and `/logo-dark` (without a dark one the
  dark theme shows the light one), the colour as a generated stylesheet at `/o/<org>/branding/brand.css`. Nothing is fetched from
  outside, so it works on a network without internet access.

Who may set it: the organization's administrators and super admins, with a console session or a personal API token.
Service accounts may not (403); the one exception is creating an organization, where `POST /api/orgs` takes the same
`branding` object (a super admin, or the primary organization's service account with `orgs:create`), so a provisioning
pipeline can brand the organization it makes. Changes after that are a person's. Each change is audited as `org.branding`.

```bash
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$QUISORA/api/orgs/acme/branding" -d '{"primary_color": "#134e4a", "logo_light": "data:image/svg+xml;base64,PHN2Zy…"}'
```

A field left out stays as it is and `""` removes it. An invalid value is a 422 whose `field` is `logo_light`,
`logo_dark` or `primary_color` (`branding.primary_color` and so on when creating). The organization objects the API
returns carry `"branding": {"primary_color": "#134e4a", "logo_light": "<url>", "logo_dark": "<url>"}` (a logo's URL is
omitted when there is none, and `primary_color` is `""` without one).
