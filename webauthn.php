<?php

class webauthn extends rcube_plugin
{
    public $task = '?(?!logout).*';
    public $noframe = true;

    private $rc;
    private $manager;

    #[\Override]
    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config();

        $policy = $this->rc->config->get('webauthn_2fa_policy', 'optional');
        if ($policy === 'off') {
            return;
        }

        // 2FA gate: check on every request after login
        $this->add_hook('startup', [$this, 'on_startup']);
        $this->add_hook('login_after', [$this, 'on_login_after']);

        // Register verification actions (always available — needed during 2FA gate)
        $this->register_action('plugin.webauthn-verify', [$this, 'action_verify_page']);
        $this->register_action('plugin.webauthn-assert-options', [$this, 'action_assert_options']);
        $this->register_action('plugin.webauthn-assert-verify', [$this, 'action_assert_verify']);

        // Settings page
        if ($this->rc->task == 'settings') {
            $this->add_texts('localization/');
            $this->add_hook('settings_actions', [$this, 'settings_actions']);

            $this->register_action('plugin.webauthn-settings', [$this, 'action_settings']);
            $this->register_action('plugin.webauthn-register-options', [$this, 'action_register_options']);
            $this->register_action('plugin.webauthn-register-verify', [$this, 'action_register_verify']);
            $this->register_action('plugin.webauthn-delete', [$this, 'action_delete']);
            $this->register_action('plugin.webauthn-toggle', [$this, 'action_toggle']);
        }
    }

    /**
     * Get or initialize the WebAuthnManager.
     */
    private function get_manager(): WebAuthnManager
    {
        if ($this->manager === null) {
            require_once __DIR__ . '/vendor/autoload.php';
            require_once __DIR__ . '/lib/WebAuthnManager.php';

            $config = [
                'rp_name'           => $this->rc->config->get('webauthn_rp_name', 'Roundcube'),
                'rp_id'             => $this->rc->config->get('webauthn_rp_id', ''),
                'rp_origins'        => $this->rc->config->get('webauthn_rp_origins', []),
                'timeout'           => $this->rc->config->get('webauthn_timeout', 60000),
                'user_verification' => $this->rc->config->get('webauthn_user_verification', 'preferred'),
                'attestation'       => $this->rc->config->get('webauthn_attestation', 'none'),
                'attachment'        => $this->rc->config->get('webauthn_attachment', ''),
            ];

            if (empty($config['rp_id'])) {
                $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
                if (str_contains($host, ':')) {
                    $host = explode(':', $host, 2)[0];
                }
                $config['rp_id'] = $host;
            }

            $this->manager = new WebAuthnManager($this->rc->get_dbh(), $config);
            $this->manager->ensure_table();
        }

        return $this->manager;
    }

    // ----------------------------------------------------------------
    // Hooks
    // ----------------------------------------------------------------

    /**
     * startup hook — enforce 2FA gate on every request.
     */
    public function on_startup($args)
    {
        if (empty($_SESSION['user_id'])) {
            return $args;
        }

        if (empty($_SESSION['webauthn_2fa_pending'])) {
            return $args;
        }

        // Allow only whitelisted actions while 2FA is pending
        $allowed = [
            'plugin.webauthn-verify',
            'plugin.webauthn-assert-options',
            'plugin.webauthn-assert-verify',
            'logout',
        ];

        $current_action = $args['action'] ?? '';
        $current_task = $args['task'] ?? '';

        if ($current_task === 'logout' || in_array($current_action, $allowed)) {
            return $args;
        }

        // Redirect to verification page
        $this->rc->output->redirect(['_task' => 'settings', '_action' => 'plugin.webauthn-verify']);

        return $args;
    }

    /**
     * login_after hook — set 2FA pending flag if user has credentials.
     */
    public function on_login_after($args)
    {
        $policy = $this->rc->config->get('webauthn_2fa_policy', 'optional');
        $user_id = $this->rc->user->ID;

        if ($policy === 'off') {
            return $args;
        }

        $manager = $this->get_manager();

        if ($policy === 'required') {
            if ($manager->user_has_credentials($user_id)) {
                $_SESSION['webauthn_2fa_pending'] = true;
            }
            // If no credentials under 'required' policy, let them through
            // (they'll be nagged in settings to register a key)
            return $args;
        }

        // policy === 'optional'
        $enabled = $this->rc->config->get('webauthn_2fa_enabled', false);
        if ($enabled && $manager->user_has_credentials($user_id)) {
            $_SESSION['webauthn_2fa_pending'] = true;
        }

        return $args;
    }

    /**
     * settings_actions hook — add "Security Keys" section.
     */
    public function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.webauthn-settings',
            'class'  => 'webauthn',
            'label'  => 'securitykeys',
            'title'  => 'securitykeys_title',
            'domain' => 'webauthn',
        ];

        return $args;
    }

    // ----------------------------------------------------------------
    // Actions: 2FA verification
    // ----------------------------------------------------------------

    /**
     * Render the 2FA verification page.
     */
    public function action_verify_page()
    {
        $this->add_texts('localization/');
        $this->include_stylesheet($this->local_skin_path() . '/webauthn.css');
        $this->include_script('js/webauthn.js');

        $this->rc->output->set_env('webauthn_mode', 'verify');
        $this->rc->output->set_pagetitle($this->gettext('twofactor_verification'));

        $this->register_handler('plugin.body', [$this, 'verify_body']);
        $this->rc->output->send('webauthn.webauthn_verify');
    }

    /**
     * Generate the body HTML for the verification page.
     */
    public function verify_body()
    {
        $this->rc->output->add_label(
            'webauthn.verifying',
            'webauthn.tap_your_key',
            'webauthn.verification_failed',
            'webauthn.verification_success',
            'webauthn.retry'
        );

        $html = html::div(['id' => 'webauthn-verify-container', 'class' => 'formcontainer'],
            html::tag('h2', ['class' => 'boxtitle'], $this->gettext('twofactor_verification'))
            . html::div(['id' => 'webauthn-status', 'class' => 'boxcontent'],
                html::p(['id' => 'webauthn-message'], $this->gettext('tap_your_key'))
                . html::div(['id' => 'webauthn-error', 'class' => 'error', 'style' => 'display:none'], '')
                . html::p(['class' => 'formbuttons'],
                    html::tag('button', [
                        'type'    => 'button',
                        'id'      => 'webauthn-retry-btn',
                        'class'   => 'btn btn-secondary',
                        'style'   => 'display:none',
                        'onclick' => 'webauthn_start_assertion()',
                    ], $this->gettext('retry'))
                    . ' '
                    . html::tag('a', [
                        'href'  => './?_task=logout&_token=' . $this->rc->get_request_token(),
                        'class' => 'btn btn-danger',
                    ], $this->gettext('logout'))
                )
            )
        );

        return $html;
    }

    /**
     * AJAX: return assertion challenge options.
     */
    public function action_assert_options()
    {
        $user_id = $this->rc->user->ID;
        $manager = $this->get_manager();

        try {
            $result = $manager->begin_assertion($user_id);

            $_SESSION['webauthn_challenge'] = $result['challenge'];

            $this->rc->output->command('plugin.webauthn-assert-options', [
                'success' => true,
                'options' => $result['args'],
            ]);
        } catch (\Exception $e) {
            $this->rc->output->command('plugin.webauthn-assert-options', [
                'success' => false,
                'error'   => $e->getMessage(),
            ]);
        }

        $this->rc->output->send();
    }

    /**
     * AJAX: validate assertion response.
     */
    public function action_assert_verify()
    {
        if (!$this->rc->check_request(rcube_utils::INPUT_POST)) {
            $this->rc->output->command('plugin.webauthn-assert-result', [
                'success' => false,
                'error'   => 'Invalid request token',
            ]);
            $this->rc->output->send();
            return;
        }

        $challenge = $_SESSION['webauthn_challenge'] ?? null;
        $this->rc->session->remove('webauthn_challenge'); // One-shot

        if (!$challenge) {
            $this->rc->output->command('plugin.webauthn-assert-result', [
                'success' => false,
                'error'   => 'No pending challenge',
            ]);
            $this->rc->output->send();
            return;
        }

        $credential_id   = rcube_utils::get_input_string('credentialId', rcube_utils::INPUT_POST);
        $client_data      = rcube_utils::get_input_string('clientDataJSON', rcube_utils::INPUT_POST);
        $authenticator_data = rcube_utils::get_input_string('authenticatorData', rcube_utils::INPUT_POST);
        $signature         = rcube_utils::get_input_string('signature', rcube_utils::INPUT_POST);

        $user_id = $this->rc->user->ID;
        $manager = $this->get_manager();

        try {
            $ok = $manager->finish_assertion(
                $user_id,
                $challenge,
                $credential_id,
                $client_data,
                $authenticator_data,
                $signature
            );

            if ($ok) {
                $this->rc->session->remove('webauthn_2fa_pending');

                rcube::write_log('webauthn', sprintf(
                    'Successful 2FA for user %s (ID: %d) from %s',
                    $this->rc->get_user_name(), $user_id, rcube_utils::remote_ip()
                ));

                $this->rc->output->command('plugin.webauthn-assert-result', [
                    'success'  => true,
                    'redirect' => './?_task=mail',
                ]);
            } else {
                $this->rc->output->command('plugin.webauthn-assert-result', [
                    'success' => false,
                    'error'   => 'Verification failed',
                ]);
            }
        } catch (\Exception $e) {
            rcube::write_log('webauthn', sprintf(
                'Failed 2FA for user %s (ID: %d): %s',
                $this->rc->get_user_name(), $user_id, $e->getMessage()
            ));

            $this->rc->output->command('plugin.webauthn-assert-result', [
                'success' => false,
                'error'   => $e->getMessage(),
            ]);
        }

        $this->rc->output->send();
    }

    // ----------------------------------------------------------------
    // Actions: Settings page
    // ----------------------------------------------------------------

    /**
     * Render the security keys settings page.
     */
    public function action_settings()
    {
        $this->add_texts('localization/');
        $this->include_stylesheet($this->local_skin_path() . '/webauthn.css');
        $this->include_script('js/webauthn.js');

        $this->rc->output->set_env('webauthn_mode', 'settings');
        $this->rc->output->set_env('webauthn_policy', $this->rc->config->get('webauthn_2fa_policy', 'optional'));

        $user_id = $this->rc->user->ID;
        $manager = $this->get_manager();
        $credentials = $manager->get_credentials($user_id);

        // Check if user has 2FA enabled (for optional policy)
        $enabled = $this->rc->config->get('webauthn_2fa_enabled', false);
        $this->rc->output->set_env('webauthn_enabled', (bool) $enabled);

        $this->rc->output->set_pagetitle($this->gettext('securitykeys'));
        $this->register_handler('plugin.body', [$this, 'settings_body']);
        $this->rc->output->send('plugin');
    }

    /**
     * Generate the body HTML for the settings page.
     */
    public function settings_body()
    {
        $this->rc->output->add_label(
            'webauthn.securitykeys',
            'webauthn.register_key',
            'webauthn.delete_confirm',
            'webauthn.no_keys',
            'webauthn.enable_2fa',
            'webauthn.disable_2fa',
            'webauthn.key_name',
            'webauthn.registering',
            'webauthn.registration_success',
            'webauthn.registration_failed',
            'webauthn.delete_last_key_required',
            'webauthn.tap_your_key'
        );

        $user_id = $this->rc->user->ID;
        $manager = $this->get_manager();
        $credentials = $manager->get_credentials($user_id);
        $policy = $this->rc->config->get('webauthn_2fa_policy', 'optional');
        $enabled = $this->rc->config->get('webauthn_2fa_enabled', false);

        // Build credentials table
        $table = new html_table([
            'id'    => 'webauthn-keys-table',
            'class' => 'listing iconized',
            'cols'  => 4,
        ]);

        $table->add_header('name', $this->gettext('key_name'));
        $table->add_header('created', $this->gettext('created'));
        $table->add_header('lastused', $this->gettext('last_used'));
        $table->add_header('actions', '');

        if (empty($credentials)) {
            $table->add(['colspan' => 4, 'class' => 'empty'], $this->gettext('no_keys'));
        } else {
            foreach ($credentials as $cred) {
                $table->add('name', rcube::Q($cred['description']));
                $table->add('created', rcube::Q($cred['created_at']));
                $table->add('lastused', $cred['last_used_at'] ? rcube::Q($cred['last_used_at']) : $this->gettext('never'));
                $table->add('actions', html::tag('button', [
                    'type'    => 'button',
                    'class'   => 'btn btn-sm btn-danger webauthn-delete-btn',
                    'data-id' => $cred['id'],
                    'onclick' => 'webauthn_delete_key(' . (int) $cred['id'] . ')',
                ], $this->gettext('delete')));
            }
        }

        // Toggle section (only for optional policy)
        $toggle_html = '';
        if ($policy === 'optional') {
            $checkbox = new html_checkbox([
                'name'    => 'webauthn_enabled',
                'id'      => 'webauthn-toggle',
                'value'   => '1',
                'onchange' => 'webauthn_toggle_2fa(this.checked)',
            ]);

            $toggle_html = html::div(['class' => 'form-group row', 'id' => 'webauthn-toggle-row'],
                html::label(['for' => 'webauthn-toggle', 'class' => 'col-form-label'],
                    $this->gettext('enable_2fa'))
                . html::span(['class' => 'input-group'],
                    $checkbox->show($enabled ? '1' : ''))
            );
        }

        // Register button
        $register_html = html::div(['class' => 'formbuttons footerleft'],
            html::tag('button', [
                'type'    => 'button',
                'id'      => 'webauthn-register-btn',
                'class'   => 'btn btn-primary',
                'onclick' => 'webauthn_register_key()',
            ], $this->gettext('register_key'))
        );

        return html::div(['id' => 'prefs-title', 'class' => 'boxtitle'], $this->gettext('securitykeys'))
            . html::div(['class' => 'box formcontainer scroller'],
                html::div(['class' => 'boxcontent formcontent'],
                    $table->show()
                    . $toggle_html
                )
                . $register_html
            );
    }

    /**
     * AJAX: return registration challenge options.
     */
    public function action_register_options()
    {
        if (!$this->rc->check_request(rcube_utils::INPUT_GET)) {
            $this->rc->output->command('plugin.webauthn-register-options', [
                'success' => false,
                'error'   => 'Invalid request token',
            ]);
            $this->rc->output->send();
            return;
        }

        $description = rcube_utils::get_input_string('description', rcube_utils::INPUT_GET);
        $description = trim($description);
        if (empty($description)) {
            $description = 'Security Key';
        }
        $description = mb_substr($description, 0, 64);

        $user_id = $this->rc->user->ID;
        $username = $this->rc->get_user_name();
        $manager = $this->get_manager();

        try {
            $result = $manager->begin_registration($user_id, $username, $description);

            $_SESSION['webauthn_reg_challenge'] = $result['challenge'];
            $_SESSION['webauthn_reg_description'] = $result['description'];

            $this->rc->output->command('plugin.webauthn-register-options', [
                'success' => true,
                'options' => $result['args'],
            ]);
        } catch (\Exception $e) {
            $this->rc->output->command('plugin.webauthn-register-options', [
                'success' => false,
                'error'   => $e->getMessage(),
            ]);
        }

        $this->rc->output->send();
    }

    /**
     * AJAX: validate registration (attestation) response.
     */
    public function action_register_verify()
    {
        if (!$this->rc->check_request(rcube_utils::INPUT_POST)) {
            $this->rc->output->command('plugin.webauthn-register-result', [
                'success' => false,
                'error'   => 'Invalid request token',
            ]);
            $this->rc->output->send();
            return;
        }

        $challenge = $_SESSION['webauthn_reg_challenge'] ?? null;
        $description = $_SESSION['webauthn_reg_description'] ?? 'Security Key';
        $this->rc->session->remove('webauthn_reg_challenge');
        $this->rc->session->remove('webauthn_reg_description');

        if (!$challenge) {
            $this->rc->output->command('plugin.webauthn-register-result', [
                'success' => false,
                'error'   => 'No pending registration challenge',
            ]);
            $this->rc->output->send();
            return;
        }

        $client_data  = rcube_utils::get_input_string('clientDataJSON', rcube_utils::INPUT_POST);
        $attestation  = rcube_utils::get_input_string('attestationObject', rcube_utils::INPUT_POST);
        $transports   = rcube_utils::get_input_string('transports', rcube_utils::INPUT_POST);

        $user_id = $this->rc->user->ID;
        $manager = $this->get_manager();

        try {
            $ok = $manager->finish_registration(
                $user_id,
                $challenge,
                $client_data,
                $attestation,
                $description,
                $transports
            );

            if ($ok) {
                rcube::write_log('webauthn', sprintf(
                    'Key registered for user %s (ID: %d): %s',
                    $this->rc->get_user_name(), $user_id, $description
                ));

                $this->rc->output->command('plugin.webauthn-register-result', [
                    'success' => true,
                ]);
            } else {
                $this->rc->output->command('plugin.webauthn-register-result', [
                    'success' => false,
                    'error'   => 'Registration failed',
                ]);
            }
        } catch (\Exception $e) {
            $this->rc->output->command('plugin.webauthn-register-result', [
                'success' => false,
                'error'   => $e->getMessage(),
            ]);
        }

        $this->rc->output->send();
    }

    /**
     * AJAX: delete a credential.
     */
    public function action_delete()
    {
        if (!$this->rc->check_request(rcube_utils::INPUT_POST)) {
            $this->rc->output->command('plugin.webauthn-delete-result', [
                'success' => false,
                'error'   => 'Invalid request token',
            ]);
            $this->rc->output->send();
            return;
        }

        $cred_id = (int) rcube_utils::get_input_string('id', rcube_utils::INPUT_POST);
        $user_id = $this->rc->user->ID;
        $manager = $this->get_manager();
        $policy = $this->rc->config->get('webauthn_2fa_policy', 'optional');

        // Prevent deleting the last key under 'required' policy
        if ($policy === 'required' && $manager->count_credentials($user_id) <= 1) {
            $this->rc->output->command('plugin.webauthn-delete-result', [
                'success' => false,
                'error'   => $this->gettext('delete_last_key_required'),
            ]);
            $this->rc->output->send();
            return;
        }

        $ok = $manager->delete_credential($user_id, $cred_id);

        if ($ok) {
            rcube::write_log('webauthn', sprintf(
                'Key deleted for user %s (ID: %d): credential DB id %d',
                $this->rc->get_user_name(), $user_id, $cred_id
            ));
        }

        $this->rc->output->command('plugin.webauthn-delete-result', [
            'success' => $ok,
        ]);
        $this->rc->output->send();
    }

    /**
     * AJAX: toggle 2FA enabled/disabled (optional policy only).
     */
    public function action_toggle()
    {
        if (!$this->rc->check_request(rcube_utils::INPUT_POST)) {
            $this->rc->output->command('plugin.webauthn-toggle-result', [
                'success' => false,
                'error'   => 'Invalid request token',
            ]);
            $this->rc->output->send();
            return;
        }

        $policy = $this->rc->config->get('webauthn_2fa_policy', 'optional');
        if ($policy !== 'optional') {
            $this->rc->output->command('plugin.webauthn-toggle-result', [
                'success' => false,
                'error'   => 'Toggle only available with optional policy',
            ]);
            $this->rc->output->send();
            return;
        }

        $enabled = rcube_utils::get_input_string('enabled', rcube_utils::INPUT_POST);
        $enabled = ($enabled === '1' || $enabled === 'true');

        // If enabling, make sure the user has at least one key
        if ($enabled) {
            $manager = $this->get_manager();
            if (!$manager->user_has_credentials($this->rc->user->ID)) {
                $this->rc->output->command('plugin.webauthn-toggle-result', [
                    'success' => false,
                    'error'   => $this->gettext('register_key_first'),
                ]);
                $this->rc->output->send();
                return;
            }
        }

        $this->rc->user->save_prefs(['webauthn_2fa_enabled' => $enabled]);

        $this->rc->output->command('plugin.webauthn-toggle-result', [
            'success' => true,
            'enabled' => $enabled,
        ]);
        $this->rc->output->send();
    }
}
