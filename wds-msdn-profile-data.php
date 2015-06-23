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

	public function hooks() {
		add_filter( 'aad_sso_found_user', array( $this, 'save_profile_data' ), 10, 2 );
		add_filter( 'aad_sso_new_user', array( $this, 'save_profile_data' ), 10, 2 );
		add_filter( 'aad_sso_new_user_override', array( $this, 'find_user_with_puid' ), 10, 3 );

		add_filter( 'pre_site_option_registration', array( $this, 'can_user_register_new_blogs',  ) );

		add_action( 'admin_bar_menu', array( $this, 'maybe_add_create_blog_menu_item' ), 999 );

		add_filter( 'login_form_logout', array( $this, 'logout_if_profile_creation_fail' ), 99 );

		if ( is_admin() ) {
			add_action( 'admin_init', array( $this, 'register_settings' ), 11 );
		}

		add_action( 'show_user_profile', array( $this, 'show_avatar_on_edit_screen' ) );
		add_action( 'edit_user_profile', array( $this, 'show_avatar_on_edit_screen' ) );

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

	public function save_profile_data( $user, $jwt ) {
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

			// no profile? it's required, so redirect them to create one
			return $this->redirect_user_to_profile_creation( $puid );
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

		wp_update_user( array(
			'ID' => $user_id,
			'display_name' => sanitize_text_field( $profile_json->DisplayName ),
		) );

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

	public function find_user_with_puid( $override, $userdata, $jwt ) {

		$puid = substr( $jwt->altsecid, strrpos( $jwt->altsecid, ':' ) + 1 );

		// Try to find an existing user in WP with the PUID
		$users = get_users( array(
			'meta_key'    => '_user_puid',
			'meta_value'  => sanitize_text_field( $puid ),
			'number'      => 1,
			'count_total' => false,
		) );

		// We should ONLY have one of these
		$user = reset( $users );

		// If we have a user, log them in
		if ( ! empty( $user ) && is_a( $user, 'WP_User' ) ) {

			// update usermeta so we know who the user is next time
			update_user_meta( $user->ID, '_aad_sso_altsecid', sanitize_text_field( $jwt->altsecid ) );

			return $user;
		}

		return $override;
	}

	public function register_settings() {
		add_settings_field(
			'profile_api_request_header',
			__( 'Profile API Request Header token', 'msdn' ),
			array( $this, 'render_profile_api_request_header' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'affiliation',
			__( 'Affiliation to check', 'msdn' ),
			array( $this, 'render_affiliation' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'profile_api_endpoint',
			__( 'Profile API Endpoint', 'msdn' ),
			array( $this, 'render_profile_api_endpoint' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'profile_avatar_api_endpoint',
			__( 'Profile Avatar API Endpoint', 'msdn' ),
			array( $this, 'render_profile_avatar_api_endpoint' ),
			'aad-settings',
			'aad-directory-settings'
		);

		add_settings_field(
			'create_profile_endpoint',
			__( 'Profile-Create URL', 'msdn' ),
			array( $this, 'render_create_profile_endpoint' ),
			'aad-settings',
			'aad-directory-settings'
		);
	}

	public function render_profile_api_request_header() {
		echo '<input type="text" id="profile_api_request_header" name="aad-settings[profile_api_request_header]" value="' . esc_attr( $this->aad_settings( 'profile_api_request_header' ) ) . '" class="widefat" />';
	}

	public function render_affiliation() {
		echo '<input type="text" id="affiliation" name="aad-settings[affiliation]" value="' . esc_attr( $this->aad_settings( 'affiliation' ) ) . '" class="widefat" />';
		echo '<p>' . __( 'Affiliation determines if user is allowed to create blogs.', 'domain' ) . '</p>';
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

	public function aad_settings( $setting = '' ) {
		static $settings = null;
		$settings = is_null( $settings ) ? AADSSO_Settings::load_settings()->settings : $settings;

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
					return null;
			}

		}

		return $settings;
	}

	public function can_user_register_new_blogs( $value = '' ) {

		// If a user is a super admin, we want them to always be able to create a blog
		if ( is_multisite() && is_super_admin( get_current_user_id() ) ) {
			return 'blog';
		}

		// if the user doesn't have profile data, don't bother checking it
		$profile_data = get_user_meta( get_current_user_id(), '_user_profile_data', true );
		if ( ! $profile_data ) {
			return 'none';
		}

		// If a user doesn't have the Affliations profile field, they won't be from MS
		if ( ! isset( $profile_data->Affiliations ) || ! $profile_data->Affiliations ) {
			return 'none';
		}

		// If a user is from our set affiliation, allow them to register a blog
		$affiliation_to_check = esc_attr( $this->aad_settings( 'affiliation' ) );

		// Probably NEVER going to be a string
		if ( is_string( $profile_data->Affiliations ) && false !== strpos( $affiliation_to_check, $profile_data->Affiliations ) ) {
			return 'blog';
		}

		// Probably ALWAYS going to be an array
		if ( is_array( $profile_data->Affiliations ) && in_array( $affiliation_to_check, $profile_data->Affiliations, true ) ) {
			return 'blog';
		}

		return 'none';
	}


	/**
	 * Add 'Create a blog' menu item when applicable
	 *
	 * @since 1.0.0
	 *
	 * @param object $wp_admin_bar
	 */
	function maybe_add_create_blog_menu_item( $wp_admin_bar ) {

		// If network admin or MSFT affiliated user, allow blog creation.
		if ( current_user_can( 'manage_network' ) || 'blog' == $this->can_user_register_new_blogs() ) {
			$wp_admin_bar->add_menu( array(
				'parent' => 'site-name',
				'id'     => 'msdn-create-sites',
				'title'  => __( 'Create a Blog' ),
				'href'   => trailingslashit( esc_url( $_SERVER['SERVER_NAME'] ) ) . 'wp-signup.php',
			) );
		}

	}

	function show_avatar_on_edit_screen( $user ) { ?>
		<?php if ( $avatar = get_the_author_meta( '_user_profile_avatar_base64', $user->ID ) ) { ?>
		<table class="form-table">

			<tr>
				<th><label for="avatar"><?php _e( 'Avatar from MS Profile API', 'msdn' ); ?></label></th>

				<td>
				<?php
				echo '<img src="data:image/gif;base64,' . $avatar . '" />'; ?>
				</td>
			</tr>

		</table>
		<?php }
	}
}

$MSDN_Profiles = new MSDN_Profiles;
$MSDN_Profiles->hooks();
