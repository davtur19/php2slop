<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Print a warning if cf7 not installed or activated.
 *
 * Translations are loaded automatically by WordPress.org since WordPress 4.6,
 * so load_plugin_textdomain() is intentionally omitted.
 */
function cf7msm_contact_form_7_form_codes() {
    global $pagenow;
    if ( $pagenow != 'plugins.php' ) {
        return;
    }
    if ( defined( 'WPCF7_VERSION' ) && version_compare( WPCF7_VERSION, CF7MSM_MIN_CF7_VERSION ) >= 0 ) {
        return;
    }
    add_action( 'admin_notices', 'cf7msm_form_fields_error' );
    function cf7msm_form_fields_error() {
        wp_enqueue_script( 'thickbox' );
        $out = '<div class="error" id="messages"><p>';
        if ( defined( 'WPCF7_VERSION' ) && version_compare( WPCF7_VERSION, CF7MSM_MIN_CF7_VERSION ) < 0 ) {
            /* translators: %1$s: minimum required Contact Form 7 version. */
            $out .= sprintf( __( 'Please update Contact Form 7. Webheadcoder Multi-Step Forms for Contact Form 7 requires Contact Form 7 version %1$s or later.', 'contact-form-7-multi-step-module' ), CF7MSM_MIN_CF7_VERSION );
        } else {
            if ( file_exists( WP_PLUGIN_DIR . '/contact-form-7/wp-contact-form-7.php' ) ) {
                $out .= __( 'Contact Form 7 is installed, but <strong>you must activate Contact Form 7</strong> below for Webheadcoder Multi-Step Forms for Contact Form 7 to work.', 'contact-form-7-multi-step-module' );
            } else {
                /* translators: %1$s: URL of the Contact Form 7 installation screen. */
                $out .= sprintf( __( 'Contact Form 7 must be installed for Webheadcoder Multi-Step Forms for Contact Form 7 to work. <a href="%1$s" class="thickbox" title="Contact Form 7">Install Now.</a>', 'contact-form-7-multi-step-module' ), esc_url( admin_url( 'plugin-install.php?tab=plugin-information&plugin=contact-form-7&from=plugins&TB_iframe=true&width=600&height=550' ) ) );
            }
        }
        $out .= '</p></div>';
        echo wp_kses_post( $out );
    }

}

add_action( 'plugins_loaded', 'cf7msm_contact_form_7_form_codes', 10 );
/**
 * Allow a set of default html tags
 */
function cf7msm_kses(  $string, $additional_html = array()  ) {
    $allowed_html = array_merge( array(
        'a'      => array(
            'href'   => array(),
            'title'  => array(),
            'target' => array(),
            'class'  => array(),
        ),
        'div'    => array(
            'class' => array(),
            'id'    => array(),
        ),
        'button' => array(
            'class' => array(),
            'id'    => array(),
        ),
        'p'      => array(),
        'br'     => array(),
        'em'     => array(),
        'strong' => array(),
    ), $additional_html );
    return wp_kses( $string, $allowed_html );
}

/**
 * Return the url with the plugin url prepended.
 */
function cf7msm_url(  $path  ) {
    return plugins_url( $path, CF7MSM_PLUGIN );
}

/**
 * Start a PHP session only when plugin state is being written, or resume an
 * incoming session when plugin state is being read or removed.
 *
 * @param bool $create_for_write Whether a new session may be created.
 * @return bool Whether a PHP session is active.
 */
function cf7msm_activate_php_session(  $create_for_write = false  ) {
    if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
        return false;
    }
    $force_session = apply_filters( 'cf7msm_force_session', false );
    $allow_session = apply_filters( 'cf7msm_allow_session', $force_session );
    if ( !$allow_session || !empty( $_COOKIE['cf7msm_check'] ) ) {
        return false;
    }
    // Probe for working cookies on the first real write, then use the normal
    // JSON-cookie path immediately when sessions were allowed but not forced.
    if ( $create_for_write && !$force_session ) {
        if ( !headers_sent() ) {
            setcookie(
                'cf7msm_check',
                1,
                0,
                COOKIEPATH,
                COOKIE_DOMAIN
            );
        }
        return false;
    }
    if ( PHP_SESSION_ACTIVE === session_status() ) {
        return true;
    }
    $session_name = session_name();
    $has_incoming_id = is_string( $session_name ) && '' !== $session_name && !empty( $_COOKIE[$session_name] );
    if ( !$create_for_write && !$has_incoming_id ) {
        return false;
    }
    if ( headers_sent() ) {
        return false;
    }
    if ( !$force_session ) {
        setcookie(
            'cf7msm_check',
            1,
            0,
            COOKIEPATH,
            COOKIE_DOMAIN
        );
    }
    try {
        $started = @session_start();
    } catch ( Throwable $error ) {
        $started = false;
    }
    return $started && PHP_SESSION_ACTIVE === session_status();
}

/**
 * Check for user-specific multi-step state cookies.
 */
function cf7msm_has_state_cookies() {
    $cookie_names = array(
        'cf7msm_posted_data',
        'cf7msm-step',
        'cf7msm_prev_urls',
        'cf7msm-first-step',
        'cf7msm_big_cookie',
        'cf7msm_check'
    );
    foreach ( $cookie_names as $cookie_name ) {
        if ( isset( $_COOKIE[$cookie_name] ) ) {
            return true;
        }
    }
    $force_session = apply_filters( 'cf7msm_force_session', false );
    $allow_session = apply_filters( 'cf7msm_allow_session', $force_session );
    if ( $allow_session && isset( $_COOKIE['PHPSESSID'] ) ) {
        return true;
    }
    return false;
}

/**
 * Add scripts
 */
function cf7msm_scripts() {
    wp_enqueue_style(
        'cf7msm_styles',
        plugins_url( '/resources/cf7msm.css', CF7MSM_PLUGIN ),
        array('contact-form-7'),
        CF7MSM_VERSION
    );
    wp_enqueue_script(
        'cf7msm',
        plugins_url( '/resources/cf7msm.min.js', CF7MSM_PLUGIN ),
        array('jquery', 'contact-form-7'),
        CF7MSM_VERSION,
        true
    );
    $cf7msm_posted_data = cf7msm_remove_honeypot_fields_from_posted_data( cf7msm_get( 'cf7msm_posted_data', [] ) );
    if ( !is_array( $cf7msm_posted_data ) ) {
        $cf7msm_posted_data = array();
    }
    // Keep saved fields as JSON data; wp_localize_script() treats a reserved
    // array key as executable code. Escape HTML delimiters for the script tag.
    $posted_data_json = wp_json_encode( $cf7msm_posted_data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );
    wp_add_inline_script( 'cf7msm', 'var cf7msm_posted_data = ' . (( false === $posted_data_json ? '[]' : $posted_data_json )) . ';', 'before' );
    wp_localize_script( 'cf7msm', 'cf7msm_honeypot_field_matchers', cf7msm_get_active_honeypot_field_matchers() );
}

add_action( 'wp_enqueue_scripts', 'cf7msm_scripts' );
/**
 * Cookie attributes for saved form data, shared by writes and deletion.
 */
function cf7msm_posted_data_cookie_options(  $expires = 0  ) {
    return array(
        'expires'  => $expires,
        'path'     => COOKIEPATH,
        'domain'   => COOKIE_DOMAIN,
        'secure'   => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    );
}

/**
 *  Saves a variable to cookies or if not enabled, to session.
 */
function cf7msm_set(  $var_name, $var_value  ) {
    $var_value = wp_unslash( $var_value );
    if ( 'cf7msm_posted_data' === $var_name ) {
        $var_value = cf7msm_sanitize_posted_data( $var_value );
    }
    if ( cf7msm_activate_php_session( true ) ) {
        $_SESSION[$var_name] = $var_value;
        return;
    }
    $json_encoded = '';
    //for php < 5.4
    if ( defined( 'JSON_UNESCAPED_UNICODE' ) ) {
        $json_encoded = json_encode( $var_value, JSON_UNESCAPED_UNICODE );
    } else {
        $json_encoded = json_encode( $var_value );
    }
    if ( !headers_sent() ) {
        if ( 'cf7msm_posted_data' === $var_name ) {
            setcookie( $var_name, $json_encoded, cf7msm_posted_data_cookie_options() );
        } else {
            setcookie(
                $var_name,
                $json_encoded,
                0,
                COOKIEPATH,
                COOKIE_DOMAIN
            );
        }
    }
}

/**
 *  Get a variable from cookies or if not enabled, from session.
 */
function cf7msm_get(  $var_name, $default = ''  ) {
    $ret = $default;
    if ( cf7msm_activate_php_session( false ) ) {
        // $_SESSION values are stored by cf7msm_set(), which already unslashes them,
        // so they are only sanitized here (no request unslashing needed).
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via cf7msm_sanitize_posted_data().
        $ret = ( isset( $_SESSION[$var_name] ) ? cf7msm_sanitize_posted_data( $_SESSION[$var_name] ) : $default );
    } else {
        // Cookie values are unslashed then sanitized via cf7msm_sanitize_posted_data().
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via cf7msm_sanitize_posted_data().
        $ret = ( isset( $_COOKIE[$var_name] ) ? cf7msm_sanitize_posted_data( wp_unslash( $_COOKIE[$var_name] ) ) : $default );
        if ( is_string( $ret ) ) {
            $ret = json_decode( $ret, true );
        }
    }
    // Sanitize decoded cookie keys too, including cookies saved before this fix.
    if ( 'cf7msm_posted_data' === $var_name ) {
        $ret = cf7msm_sanitize_posted_data( $ret );
        // An empty session returns the string default; PHP 8 fatals when keys are added to it.
        if ( !is_array( $ret ) ) {
            $ret = array();
        }
    }
    // Conditional Fields plugin throws 500 error when these aren't set.
    if ( $var_name == 'cf7msm_posted_data' && class_exists( 'CF7CF' ) && method_exists( 'CF7CF', 'cf7msm_merge_post_with_cookie' ) ) {
        if ( !isset( $ret['_wpcf7cf_hidden_group_fields'] ) ) {
            $ret['_wpcf7cf_hidden_group_fields'] = '[]';
        }
        if ( !isset( $ret['_wpcf7cf_hidden_groups'] ) ) {
            $ret['_wpcf7cf_hidden_groups'] = '[]';
        }
        if ( !isset( $ret['_wpcf7cf_visible_groups'] ) ) {
            $ret['_wpcf7cf_visible_groups'] = '[]';
        }
    }
    return $ret;
}

/**
 * Convert a multistep form-tag's saved configuration to canonical options.
 */
function cf7msm_get_multistep_tag_options(  $tag  ) {
    $options = array();
    $supported_options = array(
        'first_step',
        'last_step',
        'send_email',
        'skip_save'
    );
    if ( !empty( $tag->options ) && is_array( $tag->options ) ) {
        foreach ( $supported_options as $option ) {
            if ( in_array( $option, $tag->options, true ) ) {
                $options[$option] = 1;
            }
        }
    }
    if ( !empty( $tag->values ) && is_array( $tag->values ) ) {
        $next_url = (string) reset( $tag->values );
        if ( '' !== $next_url ) {
            $options['next_url'] = $next_url;
        }
    }
    return $options;
}

/**
 * Normalize client options to the subset supported by saved multistep tags.
 */
function cf7msm_normalize_multistep_options(  $options  ) {
    if ( is_string( $options ) ) {
        $options = json_decode( stripslashes( $options ), true );
    }
    if ( !is_array( $options ) ) {
        return null;
    }
    $normalized = array();
    foreach ( array(
        'first_step',
        'last_step',
        'send_email',
        'skip_save'
    ) as $option ) {
        if ( !empty( $options[$option] ) ) {
            $normalized[$option] = 1;
        }
    }
    if ( isset( $options['next_url'] ) && is_scalar( $options['next_url'] ) && '' !== (string) $options['next_url'] ) {
        $normalized['next_url'] = (string) $options['next_url'];
    }
    return $normalized;
}

/**
 * Resolve new-format multistep options against the saved CF7 form.
 *
 * A single saved tag is always authoritative. Multiple tags are used by the
 * conditional-steps integration, so the submitted selection must exactly
 * match one of the configurations saved on the form.
 */
function cf7msm_resolve_multistep_config(  $wpcf7, $posted_data = array()  ) {
    $ret = array(
        'has_new_tag' => false,
        'is_valid'    => false,
        'options'     => array(),
        'tag'         => null,
    );
    if ( !is_object( $wpcf7 ) || !method_exists( $wpcf7, 'scan_form_tags' ) ) {
        return $ret;
    }
    $tags = $wpcf7->scan_form_tags( array(
        'type' => array('multistep'),
    ) );
    $candidates = array();
    foreach ( (array) $tags as $tag ) {
        if ( empty( $tag->name ) ) {
            continue;
        }
        $candidates[] = array(
            'options' => cf7msm_get_multistep_tag_options( $tag ),
            'tag'     => $tag,
        );
    }
    if ( empty( $candidates ) ) {
        return $ret;
    }
    $ret['has_new_tag'] = true;
    if ( 1 === count( $candidates ) ) {
        $ret['is_valid'] = true;
        $ret['options'] = $candidates[0]['options'];
        $ret['tag'] = $candidates[0]['tag'];
        return $ret;
    }
    $submitted_options = ( isset( $posted_data['cf7msm_options'] ) ? cf7msm_normalize_multistep_options( $posted_data['cf7msm_options'] ) : null );
    foreach ( $candidates as $candidate ) {
        if ( null !== $submitted_options && $candidate['options'] === $submitted_options ) {
            $ret['is_valid'] = true;
            $ret['options'] = $candidate['options'];
            $ret['tag'] = $candidate['tag'];
            return $ret;
        }
    }
    // Keep a real tag as validation context when the selection is ambiguous.
    $ret['tag'] = $candidates[0]['tag'];
    return $ret;
}

/**
 * Read the canonical step value from a saved legacy-format form.
 */
function cf7msm_get_saved_legacy_step(  $wpcf7  ) {
    if ( !is_object( $wpcf7 ) || !method_exists( $wpcf7, 'prop' ) ) {
        return '';
    }
    $formstring = $wpcf7->prop( 'form' );
    if ( preg_match( '/\\[multistep\\s+"(\\d+)-(\\d+)(?:-[^"]*)?"[^\\]]*\\]/', $formstring, $matches ) || preg_match( '/\\[hidden\\s+cf7msm-step\\s+"(\\d+)-(\\d+)"[^\\]]*\\]/', $formstring, $matches ) ) {
        return $matches[1] . '-' . $matches[2];
    }
    return '';
}

/**
 * Replace client-supplied multistep metadata with saved form configuration.
 */
function cf7msm_canonicalize_posted_multistep(  $posted_data  ) {
    $wpcf7 = WPCF7_ContactForm::get_current();
    $config = cf7msm_resolve_multistep_config( $wpcf7, $posted_data );
    unset($posted_data['_cf7msm_invalid_options']);
    if ( $config['has_new_tag'] ) {
        unset($posted_data['cf7msm-step']);
        if ( $config['is_valid'] ) {
            $posted_data['cf7msm_options'] = wp_json_encode( $config['options'] );
        } else {
            unset($posted_data['cf7msm_options']);
            $posted_data['_cf7msm_invalid_options'] = 1;
        }
        return $posted_data;
    }
    $legacy_step = cf7msm_get_saved_legacy_step( $wpcf7 );
    if ( '' !== $legacy_step ) {
        $posted_data['cf7msm-step'] = $legacy_step;
        unset($posted_data['cf7msm_options']);
        return $posted_data;
    }
    // Request fields must not turn an ordinary CF7 form into a multistep form.
    unset($posted_data['cf7msm-step'], $posted_data['cf7msm_options']);
    return $posted_data;
}

add_filter( 'wpcf7_posted_data', 'cf7msm_canonicalize_posted_multistep', 8 );
/**
 * Remove a saved variable.
 */
function cf7msm_remove(  $var_name  ) {
    if ( cf7msm_activate_php_session( false ) ) {
        if ( isset( $_SESSION[$var_name] ) ) {
            unset($_SESSION[$var_name]);
        }
    } else {
        if ( isset( $_COOKIE[$var_name] ) ) {
            if ( 'cf7msm_posted_data' === $var_name ) {
                setcookie( $var_name, '', cf7msm_posted_data_cookie_options( 1 ) );
            } else {
                setcookie(
                    $var_name,
                    '',
                    1,
                    COOKIEPATH,
                    COOKIE_DOMAIN
                );
            }
        }
    }
}

/**
 * Return true when a form-tag pipes object has mapped values.
 */
function cf7msm_has_pipes(  $pipes  ) {
    if ( empty( $pipes ) ) {
        return false;
    }
    if ( is_object( $pipes ) && method_exists( $pipes, 'zero' ) ) {
        return !$pipes->zero();
    }
    if ( is_object( $pipes ) && method_exists( $pipes, 'to_array' ) ) {
        $pipe_values = $pipes->to_array();
        return !empty( $pipe_values );
    }
    if ( is_array( $pipes ) ) {
        return !empty( $pipes );
    }
    return false;
}

/**
 * Return pipe-enabled selectable field metadata on the current form.
 */
function cf7msm_get_pipe_form_tags(  $wpcf7 = null  ) {
    if ( empty( $wpcf7 ) && class_exists( 'WPCF7_ContactForm' ) ) {
        $wpcf7 = WPCF7_ContactForm::get_current();
    }
    if ( empty( $wpcf7 ) || !method_exists( $wpcf7, 'scan_form_tags' ) ) {
        return array();
    }
    $form_tags = $wpcf7->scan_form_tags();
    if ( empty( $form_tags ) || !is_array( $form_tags ) ) {
        return array();
    }
    $pipe_form_tags = array();
    foreach ( $form_tags as $form_tag ) {
        $field_name = '';
        $field_type = '';
        $pipes = null;
        $has_free_text = false;
        if ( is_object( $form_tag ) ) {
            if ( !empty( $form_tag->name ) ) {
                $field_name = $form_tag->name;
            }
            if ( !empty( $form_tag->basetype ) ) {
                $field_type = $form_tag->basetype;
            } else {
                if ( !empty( $form_tag->type ) ) {
                    $field_type = rtrim( $form_tag->type, '*' );
                }
            }
            if ( isset( $form_tag->pipes ) ) {
                $pipes = $form_tag->pipes;
            }
            if ( method_exists( $form_tag, 'has_option' ) ) {
                $has_free_text = $form_tag->has_option( 'free_text' );
            } else {
                if ( !empty( $form_tag->options ) && is_array( $form_tag->options ) ) {
                    $has_free_text = in_array( 'free_text', $form_tag->options, true );
                }
            }
        } else {
            if ( is_array( $form_tag ) ) {
                $field_name = ( !empty( $form_tag['name'] ) ? $form_tag['name'] : '' );
                if ( !empty( $form_tag['basetype'] ) ) {
                    $field_type = $form_tag['basetype'];
                } else {
                    if ( !empty( $form_tag['type'] ) ) {
                        $field_type = rtrim( $form_tag['type'], '*' );
                    }
                }
                if ( isset( $form_tag['pipes'] ) ) {
                    $pipes = $form_tag['pipes'];
                }
                if ( !empty( $form_tag['options'] ) && is_array( $form_tag['options'] ) ) {
                    $has_free_text = in_array( 'free_text', $form_tag['options'], true );
                }
            }
        }
        if ( empty( $field_name ) || !in_array( $field_type, array('select', 'radio', 'checkbox'), true ) || !cf7msm_has_pipes( $pipes ) ) {
            continue;
        }
        $pipe_form_tags[$field_name] = array(
            'type'          => $field_type,
            'pipes'         => $pipes,
            'has_free_text' => $has_free_text,
        );
    }
    return $pipe_form_tags;
}

/**
 * Get raw request values for a field key and its array variant.
 */
function cf7msm_get_request_value_for_field(  $field_name, &$has_value  ) {
    // Nonce verification is handled by Contact Form 7 before this runs; values are
    // unslashed and sanitized via cf7msm_sanitize_posted_data().
    $has_value = false;
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- CF7 verifies the submission nonce.
    if ( isset( $_POST[$field_name] ) ) {
        $has_value = true;
        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- CF7 verifies the nonce; sanitized via cf7msm_sanitize_posted_data().
        return cf7msm_sanitize_posted_data( wp_unslash( $_POST[$field_name] ) );
    }
    $array_field_name = $field_name . '[]';
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- CF7 verifies the submission nonce.
    if ( isset( $_POST[$array_field_name] ) ) {
        $has_value = true;
        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- CF7 verifies the nonce; sanitized via cf7msm_sanitize_posted_data().
        return cf7msm_sanitize_posted_data( wp_unslash( $_POST[$array_field_name] ) );
    }
    return '';
}

/**
 * Get transformed posted-data values for a field key and its array variant.
 */
function cf7msm_get_posted_value_for_field(  $posted_data, $field_name, &$has_value  ) {
    $has_value = false;
    if ( !is_array( $posted_data ) ) {
        return '';
    }
    if ( array_key_exists( $field_name, $posted_data ) ) {
        $has_value = true;
        return $posted_data[$field_name];
    }
    $array_field_name = $field_name . '[]';
    if ( array_key_exists( $array_field_name, $posted_data ) ) {
        $has_value = true;
        return $posted_data[$array_field_name];
    }
    return '';
}

/**
 * Set posted-data value for a field key while preserving [] suffix if it exists.
 */
function cf7msm_set_posted_value_for_field(  &$posted_data, $field_name, $value  ) {
    if ( !is_array( $posted_data ) ) {
        return;
    }
    if ( array_key_exists( $field_name, $posted_data ) ) {
        $posted_data[$field_name] = $value;
        return;
    }
    $array_field_name = $field_name . '[]';
    if ( array_key_exists( $array_field_name, $posted_data ) ) {
        $posted_data[$array_field_name] = $value;
        return;
    }
    $posted_data[$field_name] = $value;
}

/**
 * Get free-text request value for a radio/checkbox field.
 */
function cf7msm_get_request_free_text_for_field(  $field_name  ) {
    $free_text_field_names = array($field_name . '_free_text', CF7MSM_FREE_TEXT_PREFIX_RADIO . $field_name);
    foreach ( array_unique( $free_text_field_names ) as $free_text_field_name ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- CF7 verifies the submission nonce.
        if ( !isset( $_POST[$free_text_field_name] ) ) {
            continue;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- CF7 verifies the nonce; sanitized via cf7msm_sanitize_posted_data().
        $free_text_value = cf7msm_sanitize_posted_data( wp_unslash( $_POST[$free_text_field_name] ) );
        if ( is_string( $free_text_value ) ) {
            return trim( $free_text_value );
        }
    }
    return '';
}

/**
 * Return configured server-side TTL for pipe map storage.
 */
function cf7msm_pipe_store_ttl() {
    $ttl = (int) apply_filters( 'cf7msm_pipe_store_ttl', 12 * HOUR_IN_SECONDS );
    if ( $ttl <= 0 ) {
        $ttl = 12 * HOUR_IN_SECONDS;
    }
    return $ttl;
}

/**
 * Return posted-data key used to persist a pipe flow id across steps.
 */
function cf7msm_pipe_flow_field_name() {
    return 'wpcf7msm_pipe_flow_id';
}

/**
 * Validate flow id format.
 */
function cf7msm_is_valid_pipe_flow_id(  $flow_id  ) {
    return is_string( $flow_id ) && preg_match( '/^[A-Za-z0-9]{20,128}$/', $flow_id );
}

/**
 * Return flow id from posted data when available.
 */
function cf7msm_get_pipe_flow_id_from_posted_data(  $posted_data = null  ) {
    if ( null === $posted_data && class_exists( 'WPCF7_Submission' ) ) {
        $submission = WPCF7_Submission::get_instance();
        if ( !empty( $submission ) && method_exists( $submission, 'get_posted_data' ) ) {
            $posted_data = $submission->get_posted_data();
        }
    }
    if ( !is_array( $posted_data ) ) {
        return '';
    }
    $flow_field_name = cf7msm_pipe_flow_field_name();
    if ( empty( $posted_data[$flow_field_name] ) ) {
        return '';
    }
    $flow_id = (string) $posted_data[$flow_field_name];
    return ( cf7msm_is_valid_pipe_flow_id( $flow_id ) ? $flow_id : '' );
}

/**
 * Return supported honeypot plugins and their field-name matchers.
 *
 * Array keys are plugin basenames. Each matcher must explicitly use either an
 * exact field name or an anchored regular expression. Regex matchers may name
 * one capture group that contains the corresponding CF7 honeypot tag name.
 * Matchers with a wrapper_selector may also be confirmed in JavaScript, where
 * the rendered form wrapper can be inspected.
 */
function cf7msm_get_honeypot_plugins() {
    $plugins = array(
        'contact-form-7-honeypot/honeypot.php' => array(array(
            'type'                  => 'regex',
            'pattern'               => '^(.+)-random-hash$',
            'honeypot_name_capture' => 1,
            'wrapper_selector'      => '[data-cf7apps-honeypot]',
        )),
        'honeypot/wp-armour.php'               => array(array(
            'type'             => 'exact',
            'value'            => 'alt_s',
            'wrapper_selector' => '.wpa_hidden_field, .altEmail_container',
        ), array(
            'type'             => 'exact',
            'value'            => get_option( 'wpa_field_name', '' ),
            'wrapper_selector' => '.wpa_hidden_field, .altEmail_container',
        )),
    );
    /**
     * Filter honeypot plugin basenames and their field-name matchers.
     *
     * @param array $plugins Plugin basenames as keys and arrays of strict
     *                       matcher descriptors as values.
     */
    return apply_filters( 'cf7msm_honeypot_plugins', $plugins );
}

/**
 * Return whether a plugin basename is active on the current site or network.
 */
function cf7msm_is_plugin_active(  $plugin  ) {
    if ( !is_string( $plugin ) || $plugin === '' ) {
        return false;
    }
    if ( !function_exists( 'is_plugin_active' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    return is_plugin_active( $plugin );
}

/**
 * Normalize and validate a honeypot field-name matcher.
 */
function cf7msm_normalize_honeypot_field_matcher(  $matcher  ) {
    if ( !is_array( $matcher ) || empty( $matcher['type'] ) ) {
        return array();
    }
    if ( $matcher['type'] === 'exact' ) {
        if ( !isset( $matcher['value'] ) || !is_string( $matcher['value'] ) ) {
            return array();
        }
        $value = $matcher['value'];
        if ( $value === '' || strlen( $value ) > 255 || preg_match( '/[\\x00-\\x1F\\x7F]/', $value ) ) {
            return array();
        }
        $normalized = array(
            'type'  => 'exact',
            'value' => $value,
        );
        if ( !cf7msm_add_honeypot_wrapper_selector( $normalized, $matcher ) ) {
            return array();
        }
        return $normalized;
    }
    if ( $matcher['type'] !== 'regex' || empty( $matcher['pattern'] ) || !is_string( $matcher['pattern'] ) ) {
        return array();
    }
    $pattern = $matcher['pattern'];
    if ( strlen( $pattern ) > 255 || $pattern[0] !== '^' || substr( $pattern, -1 ) !== '$' ) {
        return array();
    }
    // Keep expressions portable to JavaScript and avoid expensive constructs.
    if ( preg_match( '/[^\\x20-\\x7E]/', $pattern ) || strpos( $pattern, '(?' ) !== false || strpos( $pattern, '(*' ) !== false || preg_match( '/\\[(?:\\^)?\\[:\\^?[A-Za-z]+:\\]\\]/', $pattern ) || preg_match( '/\\\\[1-9]/', $pattern ) || preg_match( '/(?:^|[^\\\\])(?:[+*?]|\\{\\d+(?:,\\d*)?\\})\\+/', $pattern ) || preg_match( '/\\)(?:[+*]|\\{\\d+(?:,\\d*)?\\})/', $pattern ) ) {
        return array();
    }
    // Only allow escape sequences with identical PCRE and ECMAScript meaning.
    $portable_escapes = str_split( 'dDsSwWbBfnrt\\^$.*+?()[]{}|/-' );
    $escaped_characters = array();
    preg_match_all( '/\\\\(.)/s', $pattern, $escaped_characters );
    foreach ( $escaped_characters[1] as $escaped_character ) {
        if ( !in_array( $escaped_character, $portable_escapes, true ) ) {
            return array();
        }
    }
    $php_pattern = '~' . str_replace( '~', '\\~', $pattern ) . '~D';
    if ( @preg_match( $php_pattern, '' ) === false || preg_match( $php_pattern, '' ) === 1 ) {
        return array();
    }
    $normalized = array(
        'type'    => 'regex',
        'pattern' => $pattern,
    );
    if ( isset( $matcher['honeypot_name_capture'] ) ) {
        $capture = filter_var( $matcher['honeypot_name_capture'], FILTER_VALIDATE_INT, array(
            'options' => array(
                'min_range' => 1,
                'max_range' => 9,
            ),
        ) );
        if ( $capture === false ) {
            return array();
        }
        $normalized['honeypot_name_capture'] = $capture;
    }
    if ( !cf7msm_add_honeypot_wrapper_selector( $normalized, $matcher ) ) {
        return array();
    }
    return $normalized;
}

/**
 * Add a validated wrapper selector to a honeypot matcher when configured.
 */
function cf7msm_add_honeypot_wrapper_selector(  &$normalized, $matcher  ) {
    if ( !isset( $matcher['wrapper_selector'] ) ) {
        return true;
    }
    if ( !is_string( $matcher['wrapper_selector'] ) ) {
        return false;
    }
    $wrapper_selector = trim( $matcher['wrapper_selector'] );
    if ( $wrapper_selector === '' || strlen( $wrapper_selector ) > 255 || preg_match( '/[\\x00-\\x1F\\x7F]/', $wrapper_selector ) ) {
        return false;
    }
    $normalized['wrapper_selector'] = $wrapper_selector;
    return true;
}

/**
 * Return validated field-name matchers for active supported honeypot plugins.
 */
function cf7msm_get_active_honeypot_field_matchers() {
    $matchers = array();
    $seen_matchers = array();
    $plugins = cf7msm_get_honeypot_plugins();
    if ( !is_array( $plugins ) ) {
        return $matchers;
    }
    foreach ( $plugins as $plugin => $plugin_matchers ) {
        if ( !cf7msm_is_plugin_active( $plugin ) ) {
            continue;
        }
        if ( !is_array( $plugin_matchers ) ) {
            continue;
        }
        foreach ( $plugin_matchers as $matcher ) {
            $matcher = cf7msm_normalize_honeypot_field_matcher( $matcher );
            if ( empty( $matcher ) ) {
                continue;
            }
            $matcher_key = serialize( $matcher );
            if ( isset( $seen_matchers[$matcher_key] ) ) {
                continue;
            }
            $seen_matchers[$matcher_key] = true;
            $matchers[] = $matcher;
        }
    }
    return $matchers;
}

/**
 * Return details for the active honeypot matcher that accepts a field name.
 */
function cf7msm_get_honeypot_field_match(  $field_name  ) {
    if ( !is_string( $field_name ) || $field_name === '' || strlen( $field_name ) > 255 || preg_match( '/[\\x00-\\x1F\\x7F]/', $field_name ) ) {
        return array();
    }
    foreach ( cf7msm_get_active_honeypot_field_matchers() as $matcher ) {
        if ( $matcher['type'] === 'exact' ) {
            if ( $matcher['value'] === $field_name ) {
                return array(
                    'matcher' => $matcher,
                    'matches' => array($field_name),
                );
            }
            continue;
        }
        $matches = array();
        $php_pattern = '~(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)' . str_replace( '~', '\\~', $matcher['pattern'] ) . '~D';
        if ( preg_match( $php_pattern, $field_name, $matches ) === 1 ) {
            return array(
                'matcher' => $matcher,
                'matches' => $matches,
            );
        }
    }
    return array();
}

/**
 * Return honeypot tag names from the current CF7 form.
 */
function cf7msm_get_honeypot_form_tag_names() {
    if ( !function_exists( 'wpcf7_scan_form_tags' ) ) {
        return array();
    }
    $honeypot_field_names = array();
    $tags = wpcf7_scan_form_tags( array(
        'type' => 'honeypot',
    ) );
    if ( empty( $tags ) || !is_array( $tags ) ) {
        return $honeypot_field_names;
    }
    foreach ( $tags as $tag ) {
        $field_name = '';
        if ( is_object( $tag ) && !empty( $tag->name ) ) {
            $field_name = (string) $tag->name;
        } else {
            if ( is_array( $tag ) && !empty( $tag['name'] ) ) {
                $field_name = (string) $tag['name'];
            }
        }
        if ( $field_name !== '' ) {
            $honeypot_field_names[$field_name] = true;
        }
    }
    return $honeypot_field_names;
}

/**
 * Return Honeypot for Contact Form 7 fields that should not persist across steps.
 */
function cf7msm_get_honeypot_field_names_to_ignore(  $posted_data = array()  ) {
    if ( !is_array( $posted_data ) ) {
        return array();
    }
    $ignore_fields = array();
    $honeypot_field_names = cf7msm_get_honeypot_form_tag_names();
    foreach ( $honeypot_field_names as $field_name => $ignore ) {
        if ( array_key_exists( $field_name, $posted_data ) ) {
            $ignore_fields[$field_name] = true;
        }
    }
    foreach ( $posted_data as $key => $value ) {
        $field_match = cf7msm_get_honeypot_field_match( $key );
        if ( empty( $field_match ) ) {
            continue;
        }
        $matcher = $field_match['matcher'];
        if ( !empty( $matcher['wrapper_selector'] ) && ($matcher['type'] === 'exact' || empty( $matcher['honeypot_name_capture'] )) ) {
            continue;
        }
        if ( $matcher['type'] === 'exact' || empty( $matcher['honeypot_name_capture'] ) ) {
            $ignore_fields[$key] = true;
            continue;
        }
        $capture = $matcher['honeypot_name_capture'];
        if ( empty( $field_match['matches'][$capture] ) ) {
            continue;
        }
        $honeypot_field_id = $field_match['matches'][$capture];
        $is_known_honeypot_field = isset( $honeypot_field_names[$honeypot_field_id] );
        $is_honeypot_transient = false;
        if ( is_scalar( $value ) ) {
            $random_hash = (string) $value;
            if ( preg_match( '/^\\d{8,9}$/', $random_hash ) ) {
                $transient_data = get_transient( $honeypot_field_id . '-' . $random_hash );
                if ( is_array( $transient_data ) && !empty( $transient_data['expected_hp_name'] ) ) {
                    $is_honeypot_transient = true;
                    $ignore_fields[sanitize_key( $transient_data['expected_hp_name'] )] = true;
                }
            }
        }
        if ( !$is_known_honeypot_field && !$is_honeypot_transient ) {
            continue;
        }
        $ignore_fields[$key] = true;
        $ignore_fields[$honeypot_field_id] = true;
    }
    return $ignore_fields;
}

/**
 * Remove generated Honeypot fields before storing or replaying multistep data.
 */
function cf7msm_remove_honeypot_fields_from_posted_data(  $posted_data  ) {
    if ( !is_array( $posted_data ) ) {
        return $posted_data;
    }
    foreach ( cf7msm_get_honeypot_field_names_to_ignore( $posted_data ) as $field_name => $ignore ) {
        unset($posted_data[$field_name]);
    }
    return $posted_data;
}

/**
 * Generate a new opaque flow id.
 */
function cf7msm_pipe_generate_flow_id() {
    try {
        return bin2hex( random_bytes( 16 ) );
    } catch ( Exception $e ) {
        return wp_generate_password( 32, false, false );
    }
}

/**
 * Keep the server-selected flow id available for the current request.
 *
 * setcookie() does not update $_COOKIE, so this prevents a stale client value
 * from taking precedence later in the same request.
 */
function cf7msm_current_pipe_flow_id(  $flow_id = null  ) {
    static $current_flow_id = '';
    if ( null !== $flow_id ) {
        $current_flow_id = ( cf7msm_is_valid_pipe_flow_id( $flow_id ) ? $flow_id : '' );
    }
    return $current_flow_id;
}

/**
 * Get the current flow id (create one when requested).
 */
function cf7msm_get_pipe_flow_id(  $create = false  ) {
    $flow_id = cf7msm_current_pipe_flow_id();
    if ( !empty( $flow_id ) ) {
        return $flow_id;
    }
    $flow_id = cf7msm_get( 'cf7msm_pipe_flow_id', '' );
    if ( cf7msm_is_valid_pipe_flow_id( $flow_id ) && false !== get_transient( 'cf7msm_pipe_store_' . $flow_id ) ) {
        cf7msm_current_pipe_flow_id( $flow_id );
        return $flow_id;
    }
    // Only accept a client-carried id for an existing server-side flow. This
    // preserves cookie-less continuation without allowing arbitrary ids to
    // create new transient rows.
    $posted_flow_id = cf7msm_get_pipe_flow_id_from_posted_data();
    if ( !empty( $posted_flow_id ) && false !== get_transient( 'cf7msm_pipe_store_' . $posted_flow_id ) ) {
        cf7msm_current_pipe_flow_id( $posted_flow_id );
        return $posted_flow_id;
    }
    if ( !$create ) {
        return '';
    }
    $flow_id = cf7msm_pipe_generate_flow_id();
    cf7msm_current_pipe_flow_id( $flow_id );
    cf7msm_set( 'cf7msm_pipe_flow_id', $flow_id );
    return $flow_id;
}

/**
 * Start a new flow id for a new submission flow.
 */
function cf7msm_reset_pipe_flow_id() {
    $flow_id = cf7msm_pipe_generate_flow_id();
    cf7msm_current_pipe_flow_id( $flow_id );
    cf7msm_set( 'cf7msm_pipe_flow_id', $flow_id );
    return $flow_id;
}

/**
 * Get server-side pipe store for a flow id.
 */
function cf7msm_get_pipe_store(  $flow_id = ''  ) {
    if ( empty( $flow_id ) ) {
        $flow_id = cf7msm_get_pipe_flow_id();
    }
    if ( empty( $flow_id ) ) {
        return array();
    }
    $pipe_store = get_transient( 'cf7msm_pipe_store_' . $flow_id );
    if ( !is_array( $pipe_store ) ) {
        return array();
    }
    return $pipe_store;
}

/**
 * Save server-side pipe store for a flow id.
 */
function cf7msm_set_pipe_store(  $flow_id, $pipe_store  ) {
    if ( !cf7msm_is_valid_pipe_flow_id( $flow_id ) || !is_array( $pipe_store ) ) {
        return;
    }
    set_transient( 'cf7msm_pipe_store_' . $flow_id, $pipe_store, cf7msm_pipe_store_ttl() );
}

/**
 * Remove server-side pipe store for a flow id.
 */
function cf7msm_delete_pipe_store(  $flow_id = ''  ) {
    if ( empty( $flow_id ) ) {
        $flow_id = cf7msm_get_pipe_flow_id();
    }
    if ( !cf7msm_is_valid_pipe_flow_id( $flow_id ) ) {
        return;
    }
    delete_transient( 'cf7msm_pipe_store_' . $flow_id );
}

/**
 * Save display=>mail mappings server-side and keep posted data display-safe for state.
 */
function cf7msm_store_pipe_data(  &$cf7_posted_data, $flow_id = ''  ) {
    $pipe_form_tags = cf7msm_get_pipe_form_tags();
    if ( empty( $pipe_form_tags ) || !is_array( $cf7_posted_data ) ) {
        return;
    }
    if ( empty( $flow_id ) ) {
        $flow_id = cf7msm_get_pipe_flow_id( true );
    }
    if ( empty( $flow_id ) ) {
        return;
    }
    $pipe_store = cf7msm_get_pipe_store( $flow_id );
    $did_store_pipe_map = false;
    foreach ( $pipe_form_tags as $field_name => $field_data ) {
        $has_display_value = false;
        $display_value = cf7msm_get_request_value_for_field( $field_name, $has_display_value );
        if ( !$has_display_value ) {
            continue;
        }
        $display_values = ( is_array( $display_value ) ? array_values( $display_value ) : array($display_value) );
        $mail_values = array();
        $pipes = ( isset( $field_data['pipes'] ) ? $field_data['pipes'] : null );
        foreach ( $display_values as $display_item ) {
            $display_item = (string) $display_item;
            $mail_item = $display_item;
            if ( is_object( $pipes ) && method_exists( $pipes, 'do_pipe' ) ) {
                $mail_item = (string) $pipes->do_pipe( $display_item );
            }
            $mail_values[] = $mail_item;
            if ( $display_item !== $mail_item ) {
                if ( empty( $pipe_store[$field_name] ) || !is_array( $pipe_store[$field_name] ) ) {
                    $pipe_store[$field_name] = array();
                }
                $pipe_store[$field_name][$display_item] = $mail_item;
                $did_store_pipe_map = true;
            }
        }
        if ( !empty( $field_data['has_free_text'] ) && !empty( $display_values ) ) {
            $free_text_value = cf7msm_get_request_free_text_for_field( $field_name );
            if ( '' !== $free_text_value ) {
                $last_index = count( $display_values ) - 1;
                $display_values[$last_index] = trim( $display_values[$last_index] . ' ' . $free_text_value );
                $mail_values[$last_index] = trim( $mail_values[$last_index] . ' ' . $free_text_value );
                if ( $display_values[$last_index] !== $mail_values[$last_index] ) {
                    if ( empty( $pipe_store[$field_name] ) || !is_array( $pipe_store[$field_name] ) ) {
                        $pipe_store[$field_name] = array();
                    }
                    $pipe_store[$field_name][$display_values[$last_index]] = $mail_values[$last_index];
                    $did_store_pipe_map = true;
                }
            }
        }
        $display_state_value = ( is_array( $display_value ) ? $display_values : (( isset( $display_values[0] ) ? $display_values[0] : '' )) );
        cf7msm_set_posted_value_for_field( $cf7_posted_data, $field_name, $display_state_value );
    }
    if ( $did_store_pipe_map || !empty( $pipe_store ) ) {
        cf7msm_set_pipe_store( $flow_id, $pipe_store );
    }
}

/**
 * Apply server-side pipe mapping for a field value.
 */
function cf7msm_map_pipe_value_for_mail(  $field_name, $submitted, $pipe_store  ) {
    if ( !is_array( $pipe_store ) || empty( $pipe_store[$field_name] ) || !is_array( $pipe_store[$field_name] ) ) {
        return $submitted;
    }
    $field_map = $pipe_store[$field_name];
    if ( is_array( $submitted ) ) {
        return array_map( function ( $item ) use($field_map) {
            $item = (string) $item;
            return ( array_key_exists( $item, $field_map ) ? $field_map[$item] : $item );
        }, $submitted );
    }
    if ( null === $submitted ) {
        return $submitted;
    }
    $submitted = (string) $submitted;
    return ( array_key_exists( $submitted, $field_map ) ? $field_map[$submitted] : $submitted );
}

/**
 * Format a mapped value using CF7's default mail-tag formatting rules.
 */
function cf7msm_format_mail_tag_value(  $value, $html  ) {
    // Match Contact Form 7's default mail formatting. wp_get_list_item_separator()
    // is locale-aware but only exists in WordPress 6.0+, so it stays guarded to
    // preserve the plugin's minimum supported WordPress version (4.7).
    $separator = ', ';
    if ( 'body' === WPCF7_Mail::get_current_component_name() ) {
        if ( function_exists( 'wp_get_list_item_separator' ) ) {
            $separator = wp_get_list_item_separator();
        }
    }
    $separator = apply_filters( 'cf7msm_list_item_separator', $separator );
    $value = wpcf7_flat_join( $value, array(
        'separator' => $separator,
    ) );
    if ( $html ) {
        $value = esc_html( $value );
        $value = wptexturize( $value );
    }
    return $value;
}

/**
 * Replace piped display values with private values at mail composition time.
 */
function cf7msm_replace_pipe_value_for_mail_tag(
    $replaced,
    $submitted,
    $html,
    $mail_tag
) {
    if ( !is_object( $mail_tag ) || !method_exists( $mail_tag, 'field_name' ) ) {
        return $replaced;
    }
    if ( method_exists( $mail_tag, 'get_option' ) && $mail_tag->get_option( 'do_not_heat' ) ) {
        return $replaced;
    }
    $submission = WPCF7_Submission::get_instance();
    if ( empty( $submission ) || !method_exists( $submission, 'get_posted_data' ) ) {
        return $replaced;
    }
    $posted_data = $submission->get_posted_data();
    if ( empty( $posted_data['cf7msm-step'] ) && empty( $posted_data['cf7msm_options'] ) ) {
        return $replaced;
    }
    $flow_id = cf7msm_get_pipe_flow_id();
    if ( empty( $flow_id ) ) {
        return $replaced;
    }
    $pipe_store = cf7msm_get_pipe_store( $flow_id );
    if ( empty( $pipe_store ) ) {
        return $replaced;
    }
    $field_name = $mail_tag->field_name();
    if ( empty( $field_name ) ) {
        return $replaced;
    }
    $mapped_value = cf7msm_map_pipe_value_for_mail( $field_name, $submitted, $pipe_store );
    if ( $mapped_value === $submitted ) {
        return $replaced;
    }
    return cf7msm_format_mail_tag_value( $mapped_value, $html );
}

add_filter(
    'wpcf7_mail_tag_replaced',
    'cf7msm_replace_pipe_value_for_mail_tag',
    10,
    4
);
/**
 * Return a field value from saved data using key or key[].
 */
function cf7msm_get_saved_field_value(  $saved_data, $field_name, &$has_value  ) {
    $has_value = false;
    if ( !is_array( $saved_data ) ) {
        return '';
    }
    if ( array_key_exists( $field_name, $saved_data ) ) {
        $has_value = true;
        return $saved_data[$field_name];
    }
    $array_field_name = $field_name . '[]';
    if ( array_key_exists( $array_field_name, $saved_data ) ) {
        $has_value = true;
        return $saved_data[$array_field_name];
    }
    return '';
}

/**
 * Hide the second step of a form.  looks at hidden field 'step'.
 * Always show if the form is the first step.
 * If it's not the first step, make sure it's the next form in the steps.
 */
function cf7msm_step_2(  $cf7  ) {
    $has_wpcf7_class = class_exists( 'WPCF7_ContactForm' ) && method_exists( $cf7, 'prop' );
    $form_id = '';
    $using_new = false;
    $is_invalid = false;
    $is_post_request = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
    $is_rest_request = defined( 'REST_REQUEST' ) && REST_REQUEST;
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Only detecting a CF7 submission; CF7 verifies its own nonce.
    $is_submission = $is_post_request && ($is_rest_request || !empty( $_POST['_wpcf7'] ));
    if ( $has_wpcf7_class ) {
        $formstring = $cf7->prop( 'form' );
        $form_id = $cf7->id();
    } else {
        $formstring = $cf7->form;
        $form_id = $cf7->id;
    }
    if ( !is_admin() ) {
        $tags = $cf7->scan_form_tags( array(
            'type' => array('multistep'),
        ) );
        if ( !empty( $tags ) ) {
            // is a cf7msm form
            $is_first_step = false;
            foreach ( $tags as $tag ) {
                if ( empty( $tag->name ) ) {
                    continue;
                }
                $using_new = true;
                $options = $tag->options;
                if ( !empty( $options ) && in_array( 'first_step', $options ) ) {
                    $is_first_step = true;
                    break;
                }
            }
            if ( $using_new ) {
                $did_first_step = cf7msm_get( 'cf7msm-first-step' );
                if ( !$is_first_step && empty( $did_first_step ) ) {
                    $is_invalid = true;
                }
            }
        }
    }
    //old way - check if form has a step field
    if ( !is_admin() && (preg_match( '/\\[multistep "(\\d+)-(\\d+)-?(.*)"\\]/', $formstring, $matches ) || preg_match( '/\\[hidden cf7msm-step "(\\d+)-(\\d+)"\\]/', $formstring, $matches )) ) {
        // don't support using both new and old format
        if ( $using_new ) {
            if ( !$is_submission ) {
                $invalid_format_message = esc_html__( 'Error: This form is using two different formats of the multistep tag.', 'contact-form-7-multi-step-module' );
                if ( $has_wpcf7_class ) {
                    $cf7->set_properties( array(
                        'form' => apply_filters( 'cf7msm_error_invalid_format', $invalid_format_message, $form_id ),
                    ) );
                } else {
                    $cf7->form = apply_filters( 'cf7msm_error_invalid_format', $invalid_format_message, $form_id );
                }
            }
            return $cf7;
        }
        // TODO:  pull this out of this if statement when implementing new tag's step attribute.
        $step = cf7msm_get( 'cf7msm-step' );
        $missing_prev_step = (int) $step + 1 < $matches[1];
        if ( $missing_prev_step ) {
            $prev_urls = cf7msm_get( 'cf7msm_prev_urls' );
            if ( !empty( $prev_urls ) ) {
                foreach ( $prev_urls as $step_string => $url ) {
                    $step_parts = explode( '-', $step_string );
                    if ( !empty( $step_parts ) ) {
                        if ( (int) $step_parts[0] >= $matches[1] ) {
                            $missing_prev_step = false;
                            break;
                        }
                    }
                }
            }
        }
        if ( !isset( $matches[1] ) || $matches[1] != 1 && empty( $step ) || $matches[1] != 1 && $missing_prev_step ) {
            $is_invalid = true;
        }
    }
    if ( $is_invalid && !$is_submission ) {
        if ( $has_wpcf7_class ) {
            $cf7->set_properties( array(
                'form' => cf7msm_hide_cf7_step_message( $cf7->message( 'invalid_first_step' ), $form_id ),
            ) );
        } else {
            $cf7->form = cf7msm_hide_cf7_step_message( $cf7->message( 'invalid_first_step' ), $form_id );
        }
    }
    return $cf7;
}

add_action( 'wpcf7_contact_form', 'cf7msm_step_2' );
/**
 * Filter the message shown when a multistep step is accessed out of order.
 */
function cf7msm_hide_cf7_step_message(  $message, $form_id  ) {
    $message = apply_filters( 'cf7msm_hide_cf7_step_message', $message, $form_id );
    // Backwards compatibility with the original, unprefixed filter name. Applied
    // unconditionally so callbacks registered at any priority (including 0) run.
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Retained for backward compatibility with existing integrations.
    $message = apply_filters( 'wh_hide_cf7_step_message', $message, $form_id );
    return $message;
}

/**
 * Handle a multi-step cf7 form for cf7 3.9+
 */
function cf7msm_add_other_steps_filter(  $cf7_posted_data  ) {
    $curr_step = '';
    $last_step = '';
    $is_last_step = false;
    if ( empty( $cf7_posted_data['cf7msm-step'] ) && empty( $cf7_posted_data['cf7msm_options'] ) ) {
        return $cf7_posted_data;
    }
    if ( isset( $cf7_posted_data['cf7msm-step'] ) ) {
        if ( preg_match( '/(\\d+)-(\\d+)/', $cf7_posted_data['cf7msm-step'], $matches ) ) {
            $curr_step = $matches[1];
            $last_step = $matches[2];
            $is_last_step = $curr_step == $last_step;
        }
    }
    if ( !empty( $curr_step ) && !empty( $last_step ) ) {
        //for step-restricted back button
        $prev_urls = cf7msm_get( 'cf7msm_prev_urls' );
        if ( empty( $prev_urls ) ) {
            $prev_urls = array();
        }
        //old example:
        // on step 1,
        //    prev url {"2-3":"page-2"} will be set.
        //    back button is pressed, key "1-3" is looked up and returns undefined
        // on step 2,
        //    prev url {"3-3":"page-2"} will be set.
        //    back button is pressed, key "2-3" is looked up and returns "page-1"
        // on step 3,
        //    prev url {"4-3":"page-3"} will be set. - not used
        //    back button is pressed, key "3-3" is looked up and returns "page-2"
        // step
        $prev_urls[$curr_step + 1 . '-' . $last_step] = cf7msm_current_url();
        cf7msm_set( 'cf7msm_prev_urls', $prev_urls );
    }
    // TODO:  set curr_step and last_step for new tag when implemented.
    if ( !empty( $cf7_posted_data['cf7msm_options'] ) ) {
        $options = json_decode( stripslashes( $cf7_posted_data['cf7msm_options'] ), true );
        $is_last_step = !empty( $options['last_step'] );
    }
    $use_cookies = true;
    if ( !empty( $cf7_posted_data['cf7msm-no-ss'] ) || $use_cookies ) {
        $prev_data = cf7msm_get( 'cf7msm_posted_data', '' );
        if ( !is_array( $prev_data ) ) {
            $prev_data = array();
        }
        $prev_data = cf7msm_remove_honeypot_fields_from_posted_data( $prev_data );
        //remove empty [form] tags from posted_data so $prev_data can be stored.
        $fes = wpcf7_scan_form_tags();
        foreach ( $fes as $fe ) {
            if ( empty( $fe['name'] ) || $fe['type'] != 'form' && $fe['type'] != 'multiform' ) {
                continue;
            }
            unset($cf7_posted_data[$fe['name']]);
        }
        $free_text_keys = array();
        foreach ( $prev_data as $key => $value ) {
            if ( strpos( $key, CF7MSM_FREE_TEXT_PREFIX_RADIO ) === 0 ) {
                $free_text_keys[$key] = str_replace( CF7MSM_FREE_TEXT_PREFIX_RADIO, '', $key );
            } else {
                if ( strpos( $key, CF7MSM_FREE_TEXT_PREFIX_CHECKBOX ) === 0 ) {
                    $free_text_keys[$key] = str_replace( CF7MSM_FREE_TEXT_PREFIX_CHECKBOX, '', $key );
                } else {
                    if ( substr( $key, -10 ) === '_free_text' ) {
                        $free_text_keys[$key] = substr( $key, 0, -10 );
                    }
                }
            }
        }
        //if original key is set and not free text, remove free text to reflect posted data.
        foreach ( $free_text_keys as $free_text_key => $original_key ) {
            if ( isset( $cf7_posted_data[$original_key] ) && !isset( $cf7_posted_data[$free_text_key] ) ) {
                unset($prev_data[$free_text_key]);
            }
        }
        $cf7_posted_data = array_merge( $prev_data, $cf7_posted_data );
    }
    return $cf7_posted_data;
}

add_filter( 'wpcf7_posted_data', 'cf7msm_add_other_steps_filter', 9 );
/**
 * If use cookies and not the last step, store the values here after it's been validated.
 */
function cf7msm_store_data_steps() {
    $cf7_posted_data = WPCF7_Submission::get_instance()->get_posted_data();
    $cf7_posted_data = cf7msm_remove_honeypot_fields_from_posted_data( $cf7_posted_data );
    $is_last_step = false;
    $is_first_step = false;
    if ( empty( $cf7_posted_data['cf7msm-step'] ) && empty( $cf7_posted_data['cf7msm_options'] ) ) {
        return;
    }
    if ( !empty( $cf7_posted_data['cf7msm_options'] ) ) {
        $options = json_decode( stripslashes( $cf7_posted_data['cf7msm_options'] ), true );
        $is_last_step = !empty( $options['last_step'] );
        $is_first_step = !empty( $options['first_step'] );
    } else {
        if ( !empty( $cf7_posted_data['cf7msm-step'] ) && preg_match( '/(\\d+)-(\\d+)/', $cf7_posted_data['cf7msm-step'], $matches ) ) {
            $is_first_step = !empty( $matches[1] ) && intval( $matches[1] ) === 1;
        }
    }
    if ( $is_first_step ) {
        $flow_id = cf7msm_reset_pipe_flow_id();
    } else {
        $flow_id = cf7msm_get_pipe_flow_id( true );
    }
    if ( !empty( $flow_id ) ) {
        $cf7_posted_data[cf7msm_pipe_flow_field_name()] = $flow_id;
    }
    cf7msm_store_pipe_data( $cf7_posted_data, $flow_id );
    $use_cookies = true;
    if ( $use_cookies ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Runs during wpcf7_before_send_mail; CF7 has already verified the submission.
        $free_texts_lengths = array_filter( $_POST, function ( $key ) {
            return strpos( $key, '_cf7msm_free_text_reflen_' ) === 0;
        }, ARRAY_FILTER_USE_KEY );
        foreach ( $free_texts_lengths as $key => $len ) {
            $cf7_posted_data[$key] = intval( $len );
        }
        if ( !$is_last_step ) {
            // don't track big cookies on last step bc submitting on the last step doesn't use the cookie.
            cf7msm_track_big_cookie( $cf7_posted_data );
            cf7msm_set( 'cf7msm_posted_data', $cf7_posted_data );
        }
    }
}

add_action( 'wpcf7_before_send_mail', 'cf7msm_store_data_steps' );
/**
 * Skip sending the mail if this is a multi step form and not the last step.
 */
function cf7msm_skip_send_mail(  $skip_mail, $wpcf7  ) {
    $posted_data = WPCF7_Submission::get_instance()->get_posted_data();
    $config = cf7msm_resolve_multistep_config( $wpcf7, $posted_data );
    if ( $config['has_new_tag'] ) {
        if ( !$config['is_valid'] || empty( $config['options']['send_email'] ) ) {
            return true;
        }
        return $skip_mail;
    }
    $step_string = cf7msm_get_saved_legacy_step( $wpcf7 );
    if ( !empty( $step_string ) ) {
        $steps = explode( '-', $step_string );
        if ( $steps[0] != $steps[1] ) {
            return true;
        }
    }
    return $skip_mail;
}

add_filter(
    'wpcf7_skip_mail',
    'cf7msm_skip_send_mail',
    10,
    2
);
/**
 * Sets the current step if valid.
 */
function cf7msm_set_step(  $result, $tags  ) {
    $posted_data = WPCF7_Submission::get_instance()->get_posted_data();
    $wpcf7 = WPCF7_ContactForm::get_current();
    $config = cf7msm_resolve_multistep_config( $wpcf7, $posted_data );
    if ( $config['has_new_tag'] ) {
        $is_first_step = $config['is_valid'] && !empty( $config['options']['first_step'] );
        $missing_previous_step = !$is_first_step && empty( cf7msm_get( 'cf7msm-first-step' ) );
        if ( !$config['is_valid'] || $missing_previous_step ) {
            $result->invalidate( $config['tag'], $wpcf7->message( 'invalid_first_step' ) );
        } else {
            if ( $result->is_valid() ) {
                cf7msm_set( 'cf7msm-first-step', 1 );
            }
        }
        return $result;
    }
    if ( !empty( $posted_data['cf7msm-step'] ) ) {
        $step = $posted_data['cf7msm-step'];
        if ( preg_match( '/(\\d+)-(\\d+)/', $step, $matches ) ) {
            $curr_step = $matches[1];
            $last_step = $matches[2];
            $stored_step = cf7msm_get( 'cf7msm-step' );
            $missing_previous_step = 1 !== intval( $curr_step ) && (empty( $stored_step ) || intval( $stored_step ) + 1 < intval( $curr_step ));
            if ( $missing_previous_step ) {
                $result->invalidate( array(
                    'type'     => 'hidden',
                    'basetype' => 'hidden',
                    'name'     => 'cf7msm-step',
                ), $wpcf7->message( 'invalid_first_step' ) );
                return $result;
            }
            if ( $result->is_valid() ) {
                if ( $curr_step != $last_step ) {
                    cf7msm_set( 'cf7msm-step', $curr_step );
                }
            } else {
                $stored_step = cf7msm_get( 'cf7msm-step' );
                if ( $stored_step >= $curr_step ) {
                    //reduce it so user cannot move onto next step.
                    cf7msm_set( 'cf7msm-step', intval( $curr_step ) - 1 );
                }
            }
        }
    }
    return $result;
}

add_filter(
    'wpcf7_validate',
    'cf7msm_set_step',
    99,
    2
);
/**
 * Clean things up after mail has been sent.
 */
function cf7msm_mail_sent() {
    $posted_data = WPCF7_Submission::get_instance()->get_posted_data();
    $wpcf7 = WPCF7_ContactForm::get_current();
    $is_last_step = false;
    $no_ajax_redirect_url = '';
    if ( isset( $posted_data['cf7msm_options'] ) ) {
        $options = json_decode( stripslashes( $posted_data['cf7msm_options'] ), true );
        if ( !empty( $options['last_step'] ) ) {
            $is_last_step = true;
        }
        if ( !empty( $options['next_url'] ) ) {
            $no_ajax_redirect_url = $options['next_url'];
        }
    } else {
        if ( isset( $posted_data['cf7msm-step'] ) ) {
            // old way
            $curr_step = false;
            $last_step = false;
            $step = $posted_data['cf7msm-step'];
            if ( preg_match( '/(\\d+)-(\\d+)/', $step, $matches ) ) {
                $curr_step = $matches[1];
                $last_step = $matches[2];
            }
            if ( $last_step !== false && $curr_step == $last_step ) {
                $is_last_step = true;
            } else {
                $formstring = $wpcf7->prop( 'form' );
                // redirect when ajax is disabled and not doing rest and not doing ajax
                if ( !(defined( 'REST_REQUEST' ) && REST_REQUEST) && !(defined( 'DOING_AJAX' ) && DOING_AJAX) ) {
                    //get url from saved form, not $_POST.  be safe.
                    $no_ajax_redirect_url = cf7msm_parse_form_for_multistep( $wpcf7 );
                }
            }
        }
    }
    if ( $is_last_step ) {
        // while the cookie could have already been cut off, I don't want to falsely trigger
        // if cookies just plainly don't save. so just test on the last submission
        cf7msm_maybe_set_big_cookie_notice();
        $stats = get_option( '_cf7msm_stats', array() );
        $count = ( !empty( $stats['count'] ) ? $stats['count'] : 0 );
        $stats['count'] = 1 + $count;
        update_option( '_cf7msm_stats', $stats );
        $flow_id = cf7msm_get_pipe_flow_id();
        cf7msm_delete_pipe_store( $flow_id );
        cf7msm_remove( 'cf7msm-step' );
        cf7msm_remove( 'cf7msm_posted_data' );
        cf7msm_remove( 'cf7msm_pipe_flow_id' );
        cf7msm_remove( 'cf7msm_prev_urls' );
        cf7msm_remove( 'cf7msm-first-step' );
        cf7msm_remove( 'cf7msm_big_cookie' );
    }
    // redirect when ajax is disabled and not doing rest and not doing ajax
    if ( !(defined( 'REST_REQUEST' ) && REST_REQUEST) && !(defined( 'DOING_AJAX' ) && DOING_AJAX) ) {
        if ( empty( $no_ajax_redirect_url ) ) {
            // if using old additional_settings way
            $subject = $wpcf7->prop( 'additional_settings' );
            $pattern = '/location\\.replace\\(\'([^\']*)\'\\);/';
            preg_match( $pattern, $subject, $matches );
            if ( count( $matches ) == 2 ) {
                $no_ajax_redirect_url = $matches[1];
            }
        }
        $no_ajax_redirect_url = apply_filters( 'cf7msm_redirect_url', $no_ajax_redirect_url, $wpcf7->id() );
        if ( !empty( $no_ajax_redirect_url ) ) {
            // The next-page URL is a site-owner setting and may point to another
            // host (documented support). Allow that host through wp_safe_redirect()'s
            // validation instead of falling back to wp-admin.
            $redirect_host = wp_parse_url( $no_ajax_redirect_url, PHP_URL_HOST );
            if ( !empty( $redirect_host ) ) {
                add_filter( 'allowed_redirect_hosts', function ( $hosts ) use($redirect_host) {
                    $hosts[] = $redirect_host;
                    return $hosts;
                } );
            }
            wp_safe_redirect( esc_url_raw( $no_ajax_redirect_url ) );
            exit;
        }
    }
}

add_action( 'wpcf7_mail_sent', 'cf7msm_mail_sent' );
/**
 * Go through a wpcf7 form's formstring and find the multistep url.
 * If $steps is true, return the steps part as "<curr>-<total>", otherwise return the url.
 */
function cf7msm_parse_form_for_multistep(  $wpcf7, $steps = false  ) {
    $formstring = $wpcf7->prop( 'form' );
    if ( preg_match( '/\\[multistep "(\\d+)-(\\d+)-(.+)"\\]/', $formstring, $matches ) ) {
        if ( $steps ) {
            if ( !empty( $matches[1] ) && !empty( $matches[2] ) ) {
                return $matches[1] . '-' . $matches[2];
            }
        } else {
            if ( !empty( $matches[3] ) ) {
                return $matches[3];
            }
        }
    }
    if ( !$steps ) {
        // new way
        $tags = $wpcf7->scan_form_tags( array(
            'type' => array('multistep'),
        ) );
        if ( !empty( $tags ) ) {
            // is a cf7msm form
            $is_first_step = true;
            $has_new_version = false;
            // return last one first.
            $tags = array_reverse( $tags );
            foreach ( $tags as $tag ) {
                if ( empty( $tag->name ) ) {
                    continue;
                }
                if ( !empty( $tag->values ) ) {
                    return (string) reset( $tag->values );
                }
            }
        }
    }
    return '';
}

/**
 * Deprecated. Backward-compatible wrapper for the pre-prefix global function.
 *
 * @deprecated Use cf7msm_parse_form_for_multistep() instead.
 */
if ( !function_exists( 'parse_form_for_multistep' ) ) {
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Retained for backward compatibility with existing integrations that call this long-standing public function.
    function parse_form_for_multistep(  $wpcf7, $steps = false  ) {
        return cf7msm_parse_form_for_multistep( $wpcf7, $steps );
    }

}
/**
 * return the full url.
 */
function cf7msm_current_url() {
    $https = ( isset( $_SERVER['HTTPS'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTPS'] ) ) : '' );
    $server_name = ( isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '' );
    $server_port = ( isset( $_SERVER['SERVER_PORT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_PORT'] ) ) : '' );
    $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' );
    $page_url = 'http';
    if ( $https === 'on' ) {
        $page_url .= 's';
    }
    $page_url .= '://';
    if ( '' !== $server_port && '80' !== $server_port ) {
        $page_url .= $server_name . ':' . $server_port . $request_uri;
    } else {
        $page_url .= $server_name . $request_uri;
    }
    return esc_url( $page_url );
}

/**
 * 
 */
function cf7msm_setup_next_url(  $not_used  ) {
    global $cf7msm_redirect_urls;
    if ( empty( $cf7msm_redirect_urls ) ) {
        $cf7msm_redirect_urls = array();
    }
    $wpcf7 = WPCF7_ContactForm::get_current();
    $redirect_url = cf7msm_parse_form_for_multistep( $wpcf7 );
    $redirect_url = apply_filters( 'cf7msm_redirect_url', $redirect_url, $wpcf7->id() );
    if ( !empty( $redirect_url ) ) {
        $cf7msm_redirect_urls[$wpcf7->id()] = $redirect_url;
    }
    wp_localize_script( 'cf7msm', 'cf7msm_redirect_urls', $cf7msm_redirect_urls );
    return $not_used;
}

add_filter( 'wpcf7_form_action_url', 'cf7msm_setup_next_url' );
/**
 * Skip saving to DB if skip_save is set.
 */
function cf7msm_skip_save(  $form, $results  ) {
    $posted_data = WPCF7_Submission::get_instance()->get_posted_data();
    if ( !empty( $posted_data['cf7msm_options'] ) ) {
        $options = json_decode( stripslashes( $posted_data['cf7msm_options'] ), true );
        if ( !empty( $options['skip_save'] ) ) {
            remove_action(
                'wpcf7_submit',
                'wpcf7_flamingo_submit',
                10,
                2
            );
            remove_action( 'wpcf7_before_send_mail', 'cfdb7_before_send_mail' );
            remove_action( 'wpcf7_before_send_mail', 'vsz_cf7_before_send_email' );
        }
    }
}

add_action(
    'wpcf7_before_send_mail',
    'cf7msm_skip_save',
    9,
    2
);
/**
 * Track big cookies
 */
function cf7msm_track_big_cookie(  $posted_data  ) {
    // -1 if cookie is not set.
    $has_big_cookie = cf7msm_get( 'cf7msm_big_cookie', -1 );
    if ( cf7msm_cookie_size( $posted_data ) >= CF7MSM_COOKIE_SIZE_THRESHOLD ) {
        cf7msm_set( 'cf7msm_big_cookie', 1 );
    } else {
        if ( $has_big_cookie == -1 ) {
            cf7msm_set( 'cf7msm_big_cookie', 0 );
        }
    }
}

/**
 * Since posted data can be truncated after setting it to a cookie, 
 * get size of the actual posted_data and add then the cookie.
 */
function cf7msm_cookie_size(  $posted_data = array()  ) {
    $size = 0;
    foreach ( $posted_data as $key => $value ) {
        $size += mb_strlen( $key, '8bit' );
        $size += mb_strlen( json_encode( $value, JSON_UNESCAPED_UNICODE ), '8bit' );
    }
    if ( !empty( $_COOKIE ) ) {
        foreach ( $_COOKIE as $key => $value ) {
            if ( $key == 'cf7msm_posted_data' ) {
                continue;
            }
            $size += mb_strlen( $key, '8bit' );
            if ( is_array( $value ) ) {
                $size += mb_strlen( json_encode( $value, JSON_UNESCAPED_UNICODE ), '8bit' );
            } else {
                $size += mb_strlen( $value, '8bit' );
            }
        }
    }
    return $size;
}

/**
 * Set the notice of a big cookie.
 */
function cf7msm_maybe_set_big_cookie_notice() {
    if ( cf7msm_fs()->can_use_premium_code() ) {
        return;
    }
    $stats = get_option( '_cf7msm_stats', array() );
    $notice = ( !empty( $stats['notice-big-cookie'] ) ? $stats['notice-big-cookie'] : '' );
    $has_big_cookie = cf7msm_get( 'cf7msm_big_cookie', -1 );
    if ( $notice !== 'no' && $has_big_cookie == 1 ) {
        if ( empty( $stats['big_cookies'] ) ) {
            $stats['big_cookies'] = 0;
        }
        $stats['big_cookies'] += 1;
        update_option( '_cf7msm_stats', $stats );
    }
}

/**
 * Sanitize saved values and remove the reserved WordPress localization key.
 */
function cf7msm_sanitize_posted_data(  $value  ) {
    if ( is_array( $value ) ) {
        // WordPress appends this key as executable code in wp_localize_script().
        unset($value['l10n_print_after']);
        $value = array_map( 'cf7msm_sanitize_posted_data', $value );
    } elseif ( is_string( $value ) ) {
        $value = wp_check_invalid_utf8( $value );
        $value = wp_kses_no_null( $value );
    }
    return $value;
}
