# Polish translation notes

This branch is used to prepare and test Polish language support for PegaProx.

## Initial scope

- add `pl` to the supported language list,
- add Polish to the language switcher,
- prepare Polish translations incrementally,
- keep a safe English fallback for untranslated keys during testing.

## Bootstrap workflow

Run from the repository root on branch `polish-translation`:

```bash
git checkout polish-translation
python3 scripts/add_polish_translation_bootstrap.py
web/Dev/build.sh
```

The helper script currently performs the first safe localization pass:

- updates `web/src/contexts.js`,
- adds `pl` to `SUPPORTED_LANGS`,
- adds `🇵🇱 PL - Polski` to the language switcher,
- changes language restore checks so a saved `pl` preference can be applied,
- creates `translations.pl` in `web/src/translations.js` by copying the English map,
- replaces a starter set of common/operator-facing strings with Polish translations.

This is intentionally a bootstrap, not a complete translation. Most strings remain English in the initial `pl` map until they are translated in later passes.

## Build note

`web/Dev/build.sh` concatenates `web/src/*.js`, compiles JSX and regenerates `web/index.html`. After every change in `web/src/contexts.js` or `web/src/translations.js`, rebuild before testing the UI.

## Suggested translation order

1. Login and first-time setup.
2. Dashboard, clusters, nodes and VM/LXC basics.
3. Storage, backup and PBS.
4. Update Manager and maintenance mode.
5. Hardware monitoring and sensors.
6. ESXi / migration workflows.
7. Advanced security, compliance, DR and reporting sections.
