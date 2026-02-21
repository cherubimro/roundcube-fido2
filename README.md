# Roundcube FIDO2/WebAuthn Two-Factor Authentication

A Roundcube Webmail plugin that adds FIDO2/WebAuthn second-factor authentication using hardware security keys.

Users log in with their password first, then verify with a security key tap as a second factor. Supports YubiKey, Feitian BioPass, SoloKeys, Google Titan, and any FIDO2-compliant authenticator.

## Requirements

- Roundcube 1.6+
- PHP 8.1+
- HTTPS (WebAuthn requires a secure context)
- Composer

## Installation

### Via Composer (recommended)

From your Roundcube directory:

```bash
composer require cherubimro/roundcube-fido2
```

If the package isn't on Packagist yet, add the repository first in your Roundcube `composer.json`:

```json
"repositories": [
    { "type": "vcs", "url": "https://github.com/cherubimro/roundcube-fido2" }
]
```

### Manual installation

Copy the plugin into your Roundcube `plugins/` directory as `webauthn`:

```bash
cd /path/to/roundcube
cp -r /path/to/roundcube-fido2 plugins/webauthn
cd plugins/webauthn
composer install --no-dev
```

Copy the example configuration and edit it:

```bash
cp config.inc.php.dist config.inc.php
```

At minimum, set the relying party ID to match your domain:

```php
$config['webauthn_rp_id'] = 'mail.example.com';
```

Enable the plugin in Roundcube's `config/config.inc.php`:

```php
$config['plugins'] = ['webauthn', /* other plugins */];
```

The database table is created automatically on first use.

## Configuration

All settings go in `plugins/webauthn/config.inc.php`:

| Setting | Default | Description |
|---------|---------|-------------|
| `webauthn_2fa_policy` | `optional` | `off` / `optional` / `required` |
| `webauthn_rp_name` | `Roundcube` | Display name shown to users during ceremonies |
| `webauthn_rp_id` | auto-detect | Domain name (e.g. `mail.example.com`). Must match the domain users access Roundcube on |
| `webauthn_rp_origins` | `[]` | Allowed origins array (e.g. `['https://mail.example.com']`). Empty = auto-detect |
| `webauthn_timeout` | `60000` | Ceremony timeout in milliseconds |
| `webauthn_user_verification` | `preferred` | `preferred` / `required` / `discouraged` |
| `webauthn_attestation` | `none` | `none` / `indirect` / `direct` |
| `webauthn_attachment` | `''` | `''` (any) / `platform` / `cross-platform` |

### Policy modes

- **off** - Plugin disabled entirely.
- **optional** - Users choose whether to enable 2FA in Settings > Security Keys. This is the default.
- **required** - All users with registered keys must pass 2FA. Users without keys are allowed through (so they can register their first key).

## Usage

### Registering a key

1. Log in to Roundcube.
2. Go to **Settings > Security Keys**.
3. Click **Register New Key**.
4. Enter a name (e.g. "My YubiKey 5") and tap/touch your security key when prompted.
5. If policy is `optional`, toggle **Enable two-factor authentication**.

### Logging in with 2FA

1. Enter your username and password as usual.
2. A verification page appears: "Please insert and tap your security key."
3. Tap your key. On success, you are redirected to your inbox.

### Managing keys

- Register multiple keys for redundancy.
- Delete keys from the settings page.
- When policy is `required`, the last key cannot be deleted.

## Database

The plugin creates a `webauthn_credentials` table automatically. SQL schemas for manual creation are in the `SQL/` directory:

- `SQL/mysql.sql`
- `SQL/postgres.sql`
- `SQL/sqlite.sql`

## Security

- Challenges are single-use (consumed immediately after verification).
- CSRF protection via Roundcube's built-in request token mechanism.
- Clone detection: signature counter must strictly increase; anomalies are logged and rejected.
- All database queries are scoped to the authenticated user ID.
- The 2FA gate runs on every request via the `startup` hook. Only the verification page, assertion endpoints, and logout are whitelisted while 2FA is pending.
- Credential IDs are stored as raw binary and compared byte-for-byte.

## Supported databases

MySQL/MariaDB, PostgreSQL, and SQLite are all supported with matching schemas.

## Library

Uses [lbuchs/webauthn](https://github.com/nicklatch/WebAuthn) v2.2 -- a zero-dependency PHP WebAuthn server library.

## License

GPL-3.0-or-later (same as Roundcube).
