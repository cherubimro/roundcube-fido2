/**
 * Roundcube WebAuthn 2FA Plugin - Frontend
 */

// base64url helpers
function b64url_encode(buffer) {
    var bytes = new Uint8Array(buffer);
    var str = '';
    for (var i = 0; i < bytes.byteLength; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64url_decode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var binary = atob(str);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ----------------------------------------------------------------
// Verification mode (2FA gate)
// ----------------------------------------------------------------

function webauthn_start_assertion() {
    var msg_el = document.getElementById('webauthn-message');
    var err_el = document.getElementById('webauthn-error');
    var retry_el = document.getElementById('webauthn-retry-btn');

    if (msg_el) msg_el.textContent = rcmail.gettext('webauthn.tap_your_key');
    if (err_el) { err_el.textContent = ''; err_el.style.display = 'none'; }
    if (retry_el) retry_el.style.display = 'none';

    rcmail.http_get('plugin.webauthn-assert-options');
}

function webauthn_handle_assert_options(response) {
    if (!response.success) {
        webauthn_show_error(response.error || 'Failed to get challenge');
        return;
    }

    var options = response.options;

    // Decode challenge
    if (options.publicKey && options.publicKey.challenge) {
        options.publicKey.challenge = b64url_decode(options.publicKey.challenge);
    }

    // Decode allowCredentials
    if (options.publicKey && options.publicKey.allowCredentials) {
        for (var i = 0; i < options.publicKey.allowCredentials.length; i++) {
            options.publicKey.allowCredentials[i].id = b64url_decode(
                options.publicKey.allowCredentials[i].id
            );
        }
    }

    navigator.credentials.get(options)
        .then(function(assertion) {
            var data = {
                credentialId:     b64url_encode(assertion.rawId),
                clientDataJSON:   b64url_encode(assertion.response.clientDataJSON),
                authenticatorData: b64url_encode(assertion.response.authenticatorData),
                signature:        b64url_encode(assertion.response.signature),
            };

            rcmail.http_post('plugin.webauthn-assert-verify', data);
        })
        .catch(function(err) {
            webauthn_show_error(err.message || 'Authentication cancelled');
        });
}

function webauthn_handle_assert_result(response) {
    if (response.success && response.redirect) {
        var msg_el = document.getElementById('webauthn-message');
        if (msg_el) msg_el.textContent = rcmail.gettext('webauthn.verification_success');
        window.location.href = response.redirect;
    } else {
        webauthn_show_error(response.error || 'Verification failed');
    }
}

function webauthn_show_error(message) {
    var err_el = document.getElementById('webauthn-error');
    var retry_el = document.getElementById('webauthn-retry-btn');
    var msg_el = document.getElementById('webauthn-message');

    if (msg_el) msg_el.textContent = rcmail.gettext('webauthn.verification_failed');
    if (err_el) {
        err_el.textContent = message;
        err_el.style.display = 'block';
    }
    if (retry_el) retry_el.style.display = '';
}

// ----------------------------------------------------------------
// Settings mode (key management)
// ----------------------------------------------------------------

function webauthn_register_key() {
    var description = prompt(rcmail.gettext('webauthn.key_description_prompt'), 'My Security Key');
    if (description === null) return;

    description = description.trim() || 'Security Key';

    rcmail.display_message(rcmail.gettext('webauthn.registering'), 'loading');
    rcmail.http_get('plugin.webauthn-register-options', { description: description });
}

function webauthn_handle_register_options(response) {
    if (!response.success) {
        rcmail.hide_message('loading');
        rcmail.display_message(response.error || 'Failed to get registration options', 'error');
        return;
    }

    var options = response.options;

    // Decode challenge
    if (options.publicKey && options.publicKey.challenge) {
        options.publicKey.challenge = b64url_decode(options.publicKey.challenge);
    }

    // Decode user.id
    if (options.publicKey && options.publicKey.user && options.publicKey.user.id) {
        options.publicKey.user.id = b64url_decode(options.publicKey.user.id);
    }

    // Decode excludeCredentials
    if (options.publicKey && options.publicKey.excludeCredentials) {
        for (var i = 0; i < options.publicKey.excludeCredentials.length; i++) {
            options.publicKey.excludeCredentials[i].id = b64url_decode(
                options.publicKey.excludeCredentials[i].id
            );
        }
    }

    navigator.credentials.create(options)
        .then(function(credential) {
            var transports = '';
            if (credential.response.getTransports) {
                transports = credential.response.getTransports().join(',');
            }

            var data = {
                clientDataJSON:    b64url_encode(credential.response.clientDataJSON),
                attestationObject: b64url_encode(credential.response.attestationObject),
                transports:        transports,
            };

            rcmail.http_post('plugin.webauthn-register-verify', data);
        })
        .catch(function(err) {
            rcmail.hide_message('loading');
            rcmail.display_message(err.message || 'Registration cancelled', 'error');
        });
}

function webauthn_handle_register_result(response) {
    rcmail.hide_message('loading');

    if (response.success) {
        rcmail.display_message(rcmail.gettext('webauthn.registration_success'), 'confirmation');
        // Reload the settings page to show the new key
        window.location.reload();
    } else {
        rcmail.display_message(response.error || rcmail.gettext('webauthn.registration_failed'), 'error');
    }
}

function webauthn_delete_key(id) {
    if (!confirm(rcmail.gettext('webauthn.delete_confirm'))) {
        return;
    }

    rcmail.http_post('plugin.webauthn-delete', { id: id });
}

function webauthn_handle_delete_result(response) {
    if (response.success) {
        window.location.reload();
    } else {
        rcmail.display_message(response.error || 'Delete failed', 'error');
    }
}

function webauthn_toggle_2fa(enabled) {
    rcmail.http_post('plugin.webauthn-toggle', { enabled: enabled ? '1' : '0' });
}

function webauthn_handle_toggle_result(response) {
    if (!response.success) {
        rcmail.display_message(response.error || 'Toggle failed', 'error');
        // Revert the checkbox
        var cb = document.getElementById('webauthn-toggle');
        if (cb) cb.checked = !cb.checked;
    }
}

// ----------------------------------------------------------------
// Initialize on page load
// ----------------------------------------------------------------

if (window.rcmail) {
    rcmail.addEventListener('init', function() {
        // Check WebAuthn support
        if (!window.PublicKeyCredential) {
            var msg_el = document.getElementById('webauthn-message');
            if (msg_el) msg_el.textContent = rcmail.gettext('webauthn.webauthn_not_supported');
            var reg_btn = document.getElementById('webauthn-register-btn');
            if (reg_btn) reg_btn.disabled = true;
            return;
        }

        var mode = rcmail.env.webauthn_mode;

        // Register AJAX callbacks
        rcmail.addEventListener('plugin.webauthn-assert-options', webauthn_handle_assert_options);
        rcmail.addEventListener('plugin.webauthn-assert-result', webauthn_handle_assert_result);
        rcmail.addEventListener('plugin.webauthn-register-options', webauthn_handle_register_options);
        rcmail.addEventListener('plugin.webauthn-register-result', webauthn_handle_register_result);
        rcmail.addEventListener('plugin.webauthn-delete-result', webauthn_handle_delete_result);
        rcmail.addEventListener('plugin.webauthn-toggle-result', webauthn_handle_toggle_result);

        // Auto-start assertion on verification page
        if (mode === 'verify') {
            webauthn_start_assertion();
        }
    });
}
