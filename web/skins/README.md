# Skins

A skin replaces the look of the UI without touching templates or components. Without one the UI has its own liquid
glass look. Skins are chosen in the console, not in the configuration:

- **Super admins** keep the server's skins on **Skins** (System menu): the built-in ones (the folders here, compiled
  into the binary), which can be viewed and copied, and custom ones they add, change and remove. A custom skin is a
  stylesheet edited in the console, stored in Quisora's database (the `skins` table, replicated and backed up like
  other records) and used by every node as soon as it has replicated. The API is `/api/skins` (super admins change
  them; organization administrators list them, to choose one).
- **Each organization** chooses its skin on its branding (the overview's Branding card, or the organization dialog):
  a skin, **Default** (Quisora's own look, no skin), or **Same as the primary organization**, the default. The primary organization's
  choice is so the look of every organization that has not chosen its own (and of pages that belong to none).
  Audited with the rest of the branding (`org.branding`).
- **Preview**: the Skins page's preview buttons and the branding card's **Preview** open a dialog showing the
  organization's sign-in page, or the page it was opened from, in the skin (saved or not). It frames the page with
  `?skin=<name>` (`default` for Default, `inherit` for the primary organization's): any page shows that skin instead
  of its own, may then be framed by this site's pages (and only them), and a sign-in page shows its form to someone
  signed in too.

A skin removed leaves the organizations that chose it on the primary organization's skin until they choose another.

## Light, dark or system

Every page comes in a light and a dark theme. `ui.default_theme` (`--default-theme`, `QUISORA_DEFAULT_THEME`) picks
which one a browser gets until its user chooses:

```toml
[ui]
default_theme = "system"           # the default: follow the device's light or dark mode, and switch when it does
# default_theme = "dark"           # or always "light" or "dark"
```

The switch in the header is the user's own choice, kept in that browser (not on the account), and it wins over the
default. **Match system theme** in the user menu forgets it again. The default is the server's: organizations do not
set one of their own.

## Built-in skins

Every folder here is a built-in skin, named after the folder: adding one needs no code change, only a row below.

| Skin | |
| --- | --- |
| `matte` | Restrained: opaque surfaces with hairline borders, one royal-blue accent, square-ish corners, a solid header. |

A skin holds no logo: organizations have their own (below), and the server's is `ui.logo_light` / `ui.logo_dark`.

## Custom skins

A custom skin has a **name** (lowercase letters, digits and dashes, at most 40; not a built-in skin's or `default`),
which is set when it is added and never changes, a **display name**, and a **stylesheet** of at most 256 KB, served at
`/branding/skins/<name>.css?v=<version>` (a changed stylesheet is a new address, so browsers never keep an old one).
Start from a copy of a built-in skin (**Start from**, or **Copy to a new skin** on a built-in one): the copy's
`[data-skin="<name>"]` selectors become `[data-skin]`, which styles whichever skin is chosen, so it works under any
name. **Default** is listed too: it is no stylesheet, but its copy is Quisora's own design tokens (light, dark, and
dark for pages without JavaScript) under `[data-skin]`, every one there to change. A stylesheet whose `data-skin` selectors name only another skin (it would style nothing) is refused.

## Organization branding

An organization may have a logo of its own (and a dark-theme one) and a primary colour, which an administrator of the
organization sets on its page in the console or with `PATCH /api/orgs/{org}/branding`. Its sign-in pages
(`/o/<org>/…`) and the console of its users then show:

- its logo, and its display name in place of `ui.site_name` (page titles and header; the sign-in card drops the site
  name under the logo, since its heading already reads "Sign in to <org>"),
- its colour for buttons, links and focus rings.

Without a logo the server's is shown (`ui.logo_light` / `ui.logo_dark`) with the server's site name;
without a colour the skin's accent stays. The skin (the organization's, else the primary organization's) still decides everything else, so the organization's
logo and colour sit inside the skin's look. Organization branding holds no stylesheet of its own: it chooses one of
the server's skins, and sets the logo, the colour and the footer.

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
`logo_dark`, `primary_color`, `skin` or `footer` (`branding.primary_color` and so on when creating). The organization objects the API
returns carry `"branding": {"primary_color": "#134e4a", "logo_light": "<url>", "logo_dark": "<url>", "skin": "", "footer": ""}` (a logo's URL is
omitted when there is none, and `primary_color` is `""` without one).
