# Test fixtures

`bitwarden_export_sample.json` — a small, fully fake Bitwarden vault export
used to manually test the Bitwarden import feature (Settings → Import →
Bitwarden). See [docs/BITWARDEN_IMPORT.md](../../docs/BITWARDEN_IMPORT.md)
for the full test procedure.

**All data in this file is fake** — `*.example.invalid` domains (a reserved,
non-resolvable TLD per RFC 2606) and obviously-placeholder passwords
(`Demo-Pass-NNNN!`). Never replace this fixture with real account data.

Contents, exercising every case the importer needs to handle:

| Case | Count | Where |
|---|---|---|
| Logins | 5 | items[0..4] |
| Secure Notes | 2 | items[5..6] |
| Folders | 2 | folders[] |
| Intentional duplicate (same title+username+URL) | 1 | items[0] and items[4] are identical |
| Custom field | 1 | items[2].fields[0] ("Security Question") |
| TOTP secret | 1 | items[1].login.totp |
| Multiple URIs on one item | 1 | items[1].login.uris (2 entries) |
| Unsupported item type (Identity) | 1 | items[7] |
| Item with no folder (`folderId: null`) | 3 | items[2], items[6], items[7] |

This project has no automated test harness (it's Arduino firmware, tested
manually against real hardware — see `docs/SECURITY.md`'s own testing
section for the same convention). This fixture is meant to be uploaded
through the on-device Bitwarden import flow during manual testing, not run
through a CI test suite.
