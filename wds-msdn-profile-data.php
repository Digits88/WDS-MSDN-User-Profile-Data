<?php

/*
Plugin Name: WDS MSDN User Profile Data
Plugin URI: http://webdevstudios.com
Description: Connects the AAD SSO authentication plugin to the MSFT profile API. Requires the "Azure Active Directory First-Party Single Sign-on for WordPress" plugin.
Author: WebDevStudios
Version: 1.0.0
Author URI: http://webdevstudios.com
*/

class MSDN_Profiles {

	protected static $single_instance = null;
	protected $is_new_user = false;

	/**
	 * Creates or returns an instance of this class.
	 * @since  0.1.0
	 * @return MSDN_Profiles A single instance of this class.
	 */
	public static function get_instance() {
		if ( null === self::$single_instance ) {
			self::$single_instance = new self();
		}

		return self::$single_instance;
	}

	protected function __construct() {
		add_filter( 'aad_sso_found_user', array( $this, 'save_profile_data' ), 10, 2 );
		add_filter( 'aad_sso_new_user', array( $this, 'new_user_save_profile_data' ), 10, 2 );
		add_filter( 'aad_sso_altsecid_user', array( $this, 'find_user_with_puid' ), 10, 2 );

		add_filter( 'login_form_logout', array( $this, 'logout_if_profile_creation_fail' ), 99 );

		if ( is_admin() ) {
			add_action( 'admin_init', array( $this, 'register_settings' ), 11 );
		}

		add_action( 'show_user_profile', array( $this, 'show_avatar_on_edit_screen' ) );
		add_action( 'edit_user_profile', array( $this, 'show_avatar_on_edit_screen' ) );

		add_action( 'aad_sso_link_user_description', array( $this, 'link_user_description' ), 10, 2 );
		add_action( 'aad_sso_link_user', array( $this, 'copy_profile_data' ), 10, 2 );

	}

	/**
	 * If user canceled creating a msdn profile, log them out and send them on
	 * Mangled query strings are from redirect process from profile API
	 */
	function logout_if_profile_creation_fail( $uri ) {
		if ( ! isset( $_REQUEST['profile-cancel'] ) && ! isset( $_REQUEST['amp;amp;profile-cancel'] ) ) {
			return;
		}

		$redirect_to = isset( $_REQUEST['amp;amp;redirect_to'] ) ? $_REQUEST['amp;amp;redirect_to'] : '';
		$redirect_to = ! $redirect_to && isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : $redirect_to;
		$redirect_to = esc_url_raw( $redirect_to );

		// log user out
		wp_logout();

		// and redirect them to the location stored in the cookie
		wp_safe_redirect( $redirect_to );
		exit();
	}

	/**
	 * If user doesn't have an msdn profile, let's redirect them
	 * to the msdn profile creation page
	 */
	public function redirect_user_to_profile_creation( $puid ) {

		// Get current url w/ query strings which will be passed back
		$curr_url = remove_query_arg( 'code' );

		// Ensure it's a full url
		if ( isset( $_SERVER['HTTP_HOST'] ) && false === strpos( $curr_url, $_SERVER['HTTP_HOST'] ) ) {
			$curr_url = site_url( $curr_url, is_ssl() ? 'https' : 'http' );
		}

		// Get the logout url which wil be used if they cancel the profile creation
		$logout_url = str_replace( '&', '&amp;', wp_logout_url( site_url() ) . '&amp;profile-cancel=1' );

		$args = array(
			'referrer' => urlencode( $curr_url ),
			'cancelUrl' => urlencode( $logout_url ),
		);

		// This is the entire url for the profile creation process and redirection
		$url = add_query_arg( $args, $this->aad_settings( 'create_profile_endpoint' ) );

		// Send them there
		wp_redirect( esc_url_raw( $url ) );
		exit;
	}

	public function new_user_save_profile_data( $user, $jwt ) {
		$this->is_new_user = true;
		return $this->save_profile_data( $user, $jwt );
	}

	public function save_profile_data( $user, $jwt ) {
		if ( ! isset( $user->ID ) ) {
			return $user;
		}
		// Save the puid so we can reference easily in other places
		$puid = substr( $jwt->altsecid, strrpos( $jwt->altsecid, ':' ) + 1 );
		if ( ! $puid ) {
			return $user;
		}
		update_user_meta( $user->ID, '_user_puid', $puid );

		$processed = $this->save_user_data_from_puid( $user->ID, $puid );

		return $user;
	}

	public function save_user_data_from_puid( $user_id, $puid, $do_redirect = true ) {

		$profile_endpoint = trailingslashit( $this->aad_settings( 'profile_api_endpoint' ) ) . 'puid:' . $puid;

		// we'll use these headers for the remaining calls
		$headers = array(
			'headers' => array(
				'x-ms-applicationKey' => $this->aad_settings( 'profile_api_request_header' ),
				'Accept' => 'application/json',
			),
		);

		// Open the file using the HTTP headers set above
		$profile = wp_remote_get( $profile_endpoint, $headers );

		if ( ! isset( $profile['response']['code'] ) || $profile['response']['code'] !== 200 ) {

			if ( ! $do_redirect ) {
				return new WP_Error( 'bad_response_from_endpoint', "Bad response from endpoint: $profile_endpoint", isset( $profile['response']['code'] ) ? $profile['response']['code'] : '' );
			}

			if ( $require_profile_creation = apply_filters( 'wds_msdn_require_profile_creation', true, $this ) ) {
				// no profile? it's required, so redirect them to create one
				return $this->redirect_user_to_profile_creation( $puid );
			}

			return false;
		}

		$profile_json = json_decode( $profile['body'] );

		// save the user profile data
		update_user_meta( $user_id, '_user_profile_data', $profile_json );
		if ( isset( $profile_json->UserId ) ) {
			update_user_meta( $user_id, '_user_profile_id', sanitize_text_field( $profile_json->UserId ) );
		}

		if ( isset( $profile_json->DisplayName ) ) {
			update_user_meta( $user_id, 'nickname', sanitize_text_field( $profile_json->DisplayName ) );
		}

		$update_args = array(
			'ID' => $user_id,
			'display_name' => sanitize_text_field( $profile_json->DisplayName ),
		);

		// For testing
		// $profile_json->Affiliations = array( esc_attr( $this->aad_settings( 'affiliation' ) ) );

		if (
			$this->is_new_user
			&& ( $role = $this->aad_settings( 'affiliation_wp_role' ) )
			&& $this->has_affiliation( $profile_json )
		) {
			$update_args['role'] = esc_attr( $role );
		}

		wp_update_user( $update_args );

		// Get the avatar endpoint url by concatenating the values from the profile blob
		if ( ! isset( $profile_json->DisplayName, $profile_json->AvatarVersion ) ) {
			return new WP_Error( 'missing_profile_fields', "Missing DisplayName and AvatarVersion from endpoint: $profile_endpoint", $profile_json );
		}

		$profile_avatar_query = $this->aad_settings( 'profile_avatar_api_endpoint' ) . '?displayname='. urlencode( $profile_json->DisplayName ) .'&size=extralarge&version='. $profile_json->AvatarVersion;

		$base64_img_src = wp_remote_get( $profile_avatar_query, $headers );

		if ( ! isset( $base64_img_src['response']['code'] ) || $base64_img_src['response']['code'] !== 200 ) {
			return new WP_Error( 'bad_response_from_avatar_endpoint', "Bad response from avatar endpoint: $profile_avatar_query", isset( $base64_img_src['response']['code'] ) ? $base64_img_src['response']['code'] : '' );
		}

		// Remove wrapping quotes
		$base64_img_src = trim( $base64_img_src['body'], '"' );

		update_user_meta( $user_id, '_user_profile_avatar_base64', $base64_img_src );

		return true;
	}

	public function find_user_with_puid( $user, $aad_id ) {
		if ( $user ) {
			return $user;
		}

		$puid = substr( $aad_id, strrpos( $aad_id, ':' ) + 1 );

		// If we have a user, log them in
		if ( $user = $this->get_user_by_puid( $puid ) ) {
			// update usermeta so we know who the user is next time
			update_user_meta( $user->ID, '_aad_sso_altsecid', sanitize_text_field( $aad_id ) );
		}

		return $user;
	}

	public function get_user_by_puid( $puid ) {
		global $wpdb;
		/*
		 * We need to do this with a normal SQL query, as get_users()
		 * seems to behave unexpectedly in a multisite environment
		 */
		$query = "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '_user_puid' AND meta_value = %s";
		$query = $wpdb->prepare( $query, sanitize_text_field( $puid ) );
		$user_id = $wpdb->get_var( $query );
		$user = $user_id ? get_user_by( 'id', $user_id ) : false;

		return $user;
	}

	public function register_settings() {

		add_settings_field(
			'profile_api_request_header',
			__( 'Profile API Request Header token', 'wds_msdn' ),
			array( $this, 'render_profile_api_request_header' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'profile_api_endpoint',
			__( 'Profile API Endpoint', 'wds_msdn' ),
			array( $this, 'render_profile_api_endpoint' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'profile_avatar_api_endpoint',
			__( 'Profile Avatar API Endpoint', 'wds_msdn' ),
			array( $this, 'render_profile_avatar_api_endpoint' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'create_profile_endpoint',
			__( 'Profile-Create URL', 'wds_msdn' ),
			array( $this, 'render_create_profile_endpoint' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'affiliation',
			__( 'Profile affiliation to check', 'wds_msdn' ),
			array( $this, 'render_affiliation' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'affiliation_wp_role',
			__( 'Affiliation Role' ),
			array( $this, 'render_affiliation_wp_role' ),
			'aad-settings',
			'aad-directory-settings'
		);

	}

	public function render_profile_api_request_header() {
		echo '<input type="text" id="profile_api_request_header" name="aad-settings[profile_api_request_header]" value="' . esc_attr( $this->aad_settings( 'profile_api_request_header' ) ) . '" class="widefat" />';
	}

	public function render_affiliation() {
		echo '<input type="text" id="affiliation" name="aad-settings[affiliation]" value="' . esc_attr( $this->aad_settings( 'affiliation' ) ) . '" class="widefat" />';
		do_action( 'wds_msdn_affiliation_description', $this );
	}

	public function render_affiliation_wp_role() {
		echo '<select style="min-width: 200px;" name="aad-settings[affiliation_wp_role]" id="new_role">';
		echo '<option value="">No Role</option>';
		wp_dropdown_roles( $this->affiliation_wp_role() );
		echo '</select>';
		echo '<p class="description">' . __( 'Role for user if affiliation is met', 'wds_msdn' ) . '</p>';
	}

	public function render_profile_api_endpoint() {
		echo '<input type="text" id="profile_api_endpoint" name="aad-settings[profile_api_endpoint]" value="' . esc_attr( $this->aad_settings( 'profile_api_endpoint' ) ) . '" class="widefat" />';
	}

	public function render_profile_avatar_api_endpoint() {
		echo '<input type="text" id="profile_avatar_api_endpoint" name="aad-settings[profile_avatar_api_endpoint]" value="' . esc_attr( $this->aad_settings( 'profile_avatar_api_endpoint' ) ) . '" class="widefat" />';
	}

	public function render_create_profile_endpoint() {
		echo '<input type="text" id="create_profile_endpoint" name="aad-settings[create_profile_endpoint]" value="' . esc_attr( $this->aad_settings( 'create_profile_endpoint' ) ) . '" class="widefat" />';
	}

	public function affiliation_wp_role() {
		return $this->aad_settings( 'affiliation_wp_role', $this->aad_settings( 'default_wp_role', AADSSO_Settings::get_instance()->default_wp_role ) );
	}

	public function has_affiliation( $profile_data_or_user_id = null ) {

		$profile = $profile_data_or_user_id;

		if ( is_null( $profile_data_or_user_id ) || ! isset( $profile->Affiliations ) ) {

			$user_id = is_numeric( $profile ) ? absint( $profile ) : get_current_user_id();

			$profile = get_user_meta( $user_id, '_user_profile_data', true );

		}

		if ( ! $profile || ! isset( $profile->Affiliations ) || ! $profile->Affiliations ) {
			return false;
		}

		$affiliation = esc_attr( $this->aad_settings( 'affiliation' ) );

		// Probably NEVER going to be a string
		if ( is_string( $profile->Affiliations ) && false !== strpos( $affiliation, $profile->Affiliations ) ) {
			return true;
		}

		// Probably ALWAYS going to be an array
		return is_array( $profile->Affiliations ) && in_array( $affiliation, $profile->Affiliations, true );
	}


	public function aad_settings( $setting = '', $default = null ) {
		static $settings = null;
		$settings = is_null( $settings ) ? AADSSO_Settings::get_instance()->settings : $settings;

		if ( $setting ) {

			if ( array_key_exists( $setting, $settings ) ) {
				return $settings[ $setting ];
			}

			switch ( $setting ) {
				case 'profile_api_endpoint':
					return 'https://qa.profileapi.services.microsoft.com/profileapi/v1/Profile/id';

				case 'profile_avatar_api_endpoint':
					return 'https://qa.profileapi.services.microsoft.com/profileapi/internal/v1/avatar';

				case 'create_profile_endpoint':
					return 'https://social.msdn.microsoft.com/Profile/u/create';

				default:
					return $default;
			}

		}

		return $settings;
	}

	function show_avatar_on_edit_screen( $user ) {

		$avatar = get_the_author_meta( '_user_profile_avatar_base64', $user->ID );
		$profile_data = maybe_unserialize( get_user_meta( $user->ID, '_user_profile_data', true ) );
		$url = $this->profile_base_uri();

		$url .= $url && $profile_data && isset( $profile_data->DisplayName )
			? 'profile/' . urlencode( $profile_data->DisplayName )
			: '';

		$avatar = $avatar ? '<img src="data:image/gif;base64,' . esc_html( $avatar ) . '" />': '';
		$avatar = '<a href="' . esc_url( $url ) . '" target="_blank">' . $avatar . '<br>' . __( 'View your MSDN Profile', 'wds_msdn' ) . '</a>';

		?>
		<table class="form-table">
			<tr>
				<th><label for="avatar"><?php _e( 'MSDN Profile', 'wds_msdn' ); ?></label></th>
				<td>
					<?php echo $avatar; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	public function link_user_description() {
		if ( $url = $this->profile_base_uri() ) {
			printf( '<p class="description">%s</p>', sprintf( __( '<strong>Note:</strong> this will replace your profile fields with information from your <a href="%s/profile" target="_blank">MSDN Profile</a>.', 'wds_msdn' ), $url ) );
		}
	}

	public function copy_profile_data( $user_to_link, $user_to_keep ) {

		$fields_to_sync = array(
			'_user_puid',
			'_user_profile_data',
			'_user_profile_id',
			'nickname',
			'_user_profile_avatar_base64',
			'_aad_sso_altsecid',
		);

		// Loop profile meta fields and sync back to user that's being linked
		foreach ( $fields_to_sync as $meta_key ) {
			// Get the field
			$value = get_user_meta( $user_to_link, $meta_key, 1 );
			// and update the field on the user that's being linked
			update_user_meta( $user_to_keep, $meta_key, $value );
			// And dlete the user-meta on the user-to-remove
			delete_user_meta( $user_to_link, $meta_key );

			// if profile data...
			if ( '_user_profile_data' == $meta_key ) {
				$profile_data = maybe_unserialize( $value );

				// Then let's update the display name for the user that's being linked
				if ( $profile_data && isset( $profile_data->DisplayName ) ) {
					wp_update_user( array(
						'ID' => $user_to_keep,
						'display_name' => sanitize_text_field( $profile_data->DisplayName ),
					) );
				}
			}
		}

	}

	public function profile_base_uri() {
		$endpoint = $this->aad_settings( 'create_profile_endpoint' );
		$parts = $endpoint ? parse_url( $endpoint ) : array();
		return isset( $parts['scheme'], $parts['host'] ) ? trailingslashit( $parts['scheme'] . '://' . $parts['host'] ) : '';
	}

}

MSDN_Profiles::get_instance();
