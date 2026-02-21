<?php

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\Binary\ByteBuffer;

class WebAuthnManager
{
    private $db;
    private $config;
    private $webauthn;
    private $table;

    public function __construct($db, $config)
    {
        $this->db = $db;
        $this->config = $config;
        $this->table = $db->table_name('webauthn_credentials');

        $rp_name = $config['rp_name'] ?? 'Roundcube';
        $rp_id = $config['rp_id'] ?? $_SERVER['HTTP_HOST'] ?? 'localhost';
        // Strip port from rp_id if present
        if (str_contains($rp_id, ':')) {
            $rp_id = explode(':', $rp_id, 2)[0];
        }

        $formats = ['android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm'];

        $this->webauthn = new WebAuthn($rp_name, $rp_id, $formats, true);
    }

    /**
     * Initialize the database table if it doesn't exist.
     */
    public function ensure_table()
    {
        $result = $this->db->query("SELECT 1 FROM {$this->table} LIMIT 1");

        if ($result === false || $this->db->is_error($result)) {
            $db_type = $this->db->db_provider;
            $sql_map = [
                'mysql'    => 'mysql.sql',
                'postgres' => 'postgres.sql',
                'sqlite'   => 'sqlite.sql',
            ];

            $sql_file = $sql_map[$db_type] ?? $sql_map['mysql'];
            $sql_path = __DIR__ . '/../SQL/' . $sql_file;

            if (file_exists($sql_path)) {
                $sql = file_get_contents($sql_path);
                $this->db->exec_script($sql);
            }
        }
    }

    /**
     * Check whether a user has any registered credentials.
     */
    public function user_has_credentials($user_id): bool
    {
        return $this->count_credentials($user_id) > 0;
    }

    /**
     * Count registered credentials for a user.
     */
    public function count_credentials($user_id): int
    {
        $result = $this->db->query(
            "SELECT COUNT(*) AS cnt FROM {$this->table} WHERE user_id = ?",
            $user_id
        );

        $row = $this->db->fetch_assoc($result);

        return $row ? (int) $row['cnt'] : 0;
    }

    /**
     * Get all credentials for a user.
     */
    public function get_credentials($user_id): array
    {
        $result = $this->db->query(
            "SELECT * FROM {$this->table} WHERE user_id = ? ORDER BY created_at DESC",
            $user_id
        );

        $rows = [];
        while ($row = $this->db->fetch_assoc($result)) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Get a single credential by its DB id and user.
     */
    public function get_credential_by_db_id($user_id, $db_id): ?array
    {
        $result = $this->db->query(
            "SELECT * FROM {$this->table} WHERE id = ? AND user_id = ?",
            $db_id, $user_id
        );

        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    /**
     * Begin a registration ceremony.
     *
     * Returns ['args' => PublicKeyCredentialCreationOptions, 'challenge' => binary challenge].
     */
    public function begin_registration($user_id, $username, $description): array
    {
        $timeout = (int) ($this->config['timeout'] ?? 60000);
        $uv = ($this->config['user_verification'] ?? 'preferred') === 'required';
        $attestation = $this->config['attestation'] ?? 'none';
        $attachment = $this->config['attachment'] ?? '';

        // Map attachment config to library parameter
        $cross_platform = null;
        if ($attachment === 'cross-platform') {
            $cross_platform = true;
        } elseif ($attachment === 'platform') {
            $cross_platform = false;
        }

        // Get existing credential IDs to exclude (prevent re-registration)
        $existing = $this->get_credentials($user_id);
        $exclude = [];
        foreach ($existing as $cred) {
            $exclude[] = new ByteBuffer($cred['credential_id']);
        }

        // User handle: use a hash of user_id for privacy
        $user_handle = hash('sha256', 'webauthn_user_' . $user_id, true);

        $args = $this->webauthn->getCreateArgs(
            $user_handle,
            $username,
            $username,
            $timeout / 1000, // library takes seconds
            false,           // requireResidentKey
            $uv,
            $cross_platform,
            $exclude
        );

        // Override attestation preference
        if (isset($args->publicKey->attestation)) {
            $args->publicKey->attestation = $attestation;
        }

        $challenge = $this->webauthn->getChallenge()->getBinaryString();

        return [
            'args'        => $args,
            'challenge'   => $challenge,
            'description' => $description,
        ];
    }

    /**
     * Complete a registration ceremony.
     *
     * @param int    $user_id
     * @param string $challenge     Binary challenge from session
     * @param string $client_data   Base64url-encoded clientDataJSON
     * @param string $attestation   Base64url-encoded attestationObject
     * @param string $description   User-given name for the key
     * @param string $transports    Comma-separated transport hints from JS
     *
     * @return bool
     */
    public function finish_registration($user_id, $challenge, $client_data, $attestation, $description, $transports = ''): bool
    {
        $uv = ($this->config['user_verification'] ?? 'preferred') === 'required';
        $challenge_buf = new ByteBuffer($challenge);

        $data = $this->webauthn->processCreate(
            base64_decode(strtr($client_data, '-_', '+/')),
            base64_decode(strtr($attestation, '-_', '+/')),
            $challenge_buf,
            $uv,
            true,  // requireUserPresent
            false  // failIfRootMismatch — don't require root cert validation
        );

        // credentialId: ByteBuffer or raw binary string from the library
        if ($data->credentialId instanceof ByteBuffer) {
            $credential_id = $data->credentialId->getBinaryString();
        } else {
            // Already raw binary, not base64url
            $credential_id = $data->credentialId;
        }

        $now = $this->db->now();

        $this->db->query(
            "INSERT INTO {$this->table}"
            . " (user_id, description, credential_id, public_key, aaguid,"
            . " attestation_type, attachment, transports, sign_count,"
            . " clone_warning, user_verified, backup_eligible, created_at)"
            . " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, {$now})",
            $user_id,
            $description,
            $credential_id,
            $data->credentialPublicKey,
            $data->AAGUID ?? '',
            $data->attestationFormat ?? 'none',
            '', // attachment — not reliably reported by all authenticators
            $transports,
            (int) ($data->signatureCounter ?? 0),
            $data->userVerified ? 1 : 0,
            $data->isBackupEligible ? 1 : 0
        );

        return $this->db->insert_id('webauthn_credentials') !== false;
    }

    /**
     * Begin an assertion (authentication) ceremony.
     *
     * Returns ['args' => PublicKeyCredentialRequestOptions, 'challenge' => binary].
     */
    public function begin_assertion($user_id): array
    {
        $timeout = (int) ($this->config['timeout'] ?? 60000);
        $uv = ($this->config['user_verification'] ?? 'preferred') === 'required';

        $credentials = $this->get_credentials($user_id);
        $cred_ids = [];
        foreach ($credentials as $cred) {
            $cred_ids[] = new ByteBuffer($cred['credential_id']);
        }

        if (empty($cred_ids)) {
            throw new \RuntimeException('No credentials registered for this user');
        }

        $args = $this->webauthn->getGetArgs(
            $cred_ids,
            $timeout / 1000,
            true,  // allowUsb
            true,  // allowNfc
            true,  // allowBle
            false, // allowHybrid — disabling prevents Chrome QR/passkey dialog
            true,  // allowInternal
            $uv
        );

        $challenge = $this->webauthn->getChallenge()->getBinaryString();

        return [
            'args'      => $args,
            'challenge' => $challenge,
        ];
    }

    /**
     * Complete an assertion (authentication) ceremony.
     *
     * @param int    $user_id
     * @param string $challenge        Binary challenge from session
     * @param string $credential_id    Base64url-encoded credential ID from response
     * @param string $client_data      Base64url-encoded clientDataJSON
     * @param string $authenticator    Base64url-encoded authenticatorData
     * @param string $signature        Base64url-encoded signature
     *
     * @return bool
     */
    public function finish_assertion($user_id, $challenge, $credential_id, $client_data, $authenticator, $signature): bool
    {
        $cred_id_bin = base64_decode(strtr($credential_id, '-_', '+/'));
        $uv = ($this->config['user_verification'] ?? 'preferred') === 'required';

        // Find the matching credential
        $credential = $this->find_credential_by_raw_id($user_id, $cred_id_bin);
        if (!$credential) {
            throw new \RuntimeException('Unknown credential');
        }

        $challenge_buf = new ByteBuffer($challenge);

        $result = $this->webauthn->processGet(
            base64_decode(strtr($client_data, '-_', '+/')),
            base64_decode(strtr($authenticator, '-_', '+/')),
            base64_decode(strtr($signature, '-_', '+/')),
            $credential['public_key'],
            $challenge_buf,
            (int) $credential['sign_count'],
            $uv,
            true // requireUserPresent
        );

        if (!$result) {
            return false;
        }

        // Update sign count and last used timestamp
        $new_count = $this->webauthn->getSignatureCounter();
        $now = $this->db->now();

        if ($new_count !== null) {
            // Clone detection: counter must strictly increase (unless both are 0)
            $old_count = (int) $credential['sign_count'];
            $clone_warning = 0;
            if ($old_count > 0 && $new_count <= $old_count) {
                $clone_warning = 1;
                rcube::write_log('webauthn', sprintf(
                    'Clone warning: credential %d for user %d — counter went from %d to %d',
                    $credential['id'], $user_id, $old_count, $new_count
                ));
            }

            $this->db->query(
                "UPDATE {$this->table} SET sign_count = ?, clone_warning = ?, last_used_at = {$now} WHERE id = ?",
                $new_count, $clone_warning, $credential['id']
            );

            if ($clone_warning) {
                throw new \RuntimeException('Possible cloned authenticator detected');
            }
        } else {
            $this->db->query(
                "UPDATE {$this->table} SET last_used_at = {$now} WHERE id = ?",
                $credential['id']
            );
        }

        return true;
    }

    /**
     * Delete a credential by its DB id.
     */
    public function delete_credential($user_id, $db_id): bool
    {
        $this->db->query(
            "DELETE FROM {$this->table} WHERE id = ? AND user_id = ?",
            $db_id, $user_id
        );

        return $this->db->affected_rows() > 0;
    }

    /**
     * Find a credential by raw binary credential ID.
     */
    private function find_credential_by_raw_id($user_id, $cred_id_bin): ?array
    {
        $credentials = $this->get_credentials($user_id);
        foreach ($credentials as $cred) {
            if ($cred['credential_id'] === $cred_id_bin) {
                return $cred;
            }
        }

        return null;
    }
}
