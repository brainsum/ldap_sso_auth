<?php

namespace Drupal\ldap_sso_auth;

use Symfony\Component\HttpFoundation\Request;

/**
 * Interface LdapSsoAuthAuthenticationInterface.
 */
interface LdapSsoAuthAuthenticationInterface {

  /**
   * Set the HTTP request.
   *
   * @param Request $request
   */
  public function setRequest(Request $request);

  /**
   * Checks whether suitable authentication credentials are on the request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return bool
   *   TRUE if authentication credentials suitable for this provider are on the
   *   request, FALSE otherwise.
   */
  public function applies(Request $request);

  /**
   * Authentication prepare.
   *
   * @param Request $request
   */
  public function authenticate(Request $request);
  
  /**
   * Perform the actual logging in of the user.
   *
   * @param string $remote_user
   *   Remote user name.
   * @param string $realm
   *   Realm information.
   */
  public function loginRemoteUser($remote_user, $realm);

  /**
   * Validate an unvalidated user.
   *
   * @param string $remote_user
   *   Remote user name.
   *
   * @return \Drupal\user\Entity\User|false
   *   Returns the user if available or FALSE when the authentication is not
   *   successful.
   */
  public function validateUser($remote_user);

  /**
   * Strip the domain name from the remote user.
   *
   * @param string $remote_user
   *   The remote user name.
   *
   * @return string
   *   Returns the user without domain.
   */
  public function stripDomainName($remote_user);

  /**
   * Split username from realm.
   *
   * @param string $remote_user
   *   String to split at '@'.
   *
   * @return array
   *   Remote user and realm string separated.
   */
  public function splitUserNameRealm($remote_user);

  /**
   * Check to exclude paths from SSO.
   *
   * @param bool|string $path
   *   Path to check for exclusion.
   *
   * @return bool
   *   Path excluded or not.
   */
  public function checkExcludePath($path = FALSE);

  /**
   * Exclude default excluded paths.
   */
  public function defaultPathsToExclude();

}
