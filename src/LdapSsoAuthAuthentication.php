<?php

namespace Drupal\ldap_sso_auth;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Component\Utility\Html;
use Drupal\ldap_sso_auth\LdapSsoAuthAuthenticationInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class LdapSsoAuthAuthentication.
 */
class LdapSsoAuthAuthentication implements LdapSsoAuthAuthenticationInterface {

  /**
   * The dependency injection container.
   *
   * @var \Symfony\Component\DependencyInjection\ContainerInterface
   */
  protected $container;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $config;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * The login validator.
   *
   * @var \Drupal\ldap_authentication\Controller\LoginValidator
   */
  protected $validator;

  /**
   * The detail logger.
   *
   * @var \Drupal\ldap_servers\Logger\LdapDetailLog
   */
  protected $detailLog;

  /**
   * The request.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $request;

  /**
   * The system frontpage.
   *
   * @var string
   */
  protected $frontpage;

  /**
   * Constructs a new LdapSsoAuthAuthentication object.
   */
  public function __construct(ContainerInterface $container) {
    $this->container = $container;
    $config = $container->get('config.factory');
    $this->config = $config->get('ldap_sso_auth.settings');
    $this->frontpage = $config->get('system.site')->get('frontpage');
    $this->entityTypeManager = $container->get('entity_type.manager');
    $this->validator = $container->get('ldap_authentication.login_validator');
    $this->detailLog = $container->get('ldap.detail_log');
  }

  /**
   * {@inheritdoc}
   */
  public function setRequest(Request $request) {
    $this->request = $request;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $this->request = $request;
    if (($request->getSession() !== NULL &&
      $request->getSession()->get('uid') > 0) ||
      $this->checkExcludePath($request->getPathInfo())) {
      // Do not check remote if user is authenticated or
      // request path is excluded from remote authentication.
      return FALSE;
    }

    $sso_variable = $this->config->get('ssoVariable');
    // $request->server->set($sso_variable, 'riemann'); // For testing.
    if ($request->server->get($sso_variable) !== NULL) {
      // Check remote user is authenticated.
      return TRUE;
    }

    // SSO variable doesn't exist don't check remote authentication.
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $this->request = $request;
    $this->detailLog->log('Beginning SSO login.', [], 'ldap_sso_auth');

    $remote_user = NULL;
    $realm = NULL;

    $sso_variable = $this->config->get('ssoVariable');
    // $request->server->set($sso_variable, 'riemann'); // For testing.
    if ($request->server->get($sso_variable) !== NULL) {
      // Get name from SSO variable.
      $remote_user = $request->server->get($sso_variable);
      $remote = TRUE;
      if ($this->config->get('ssoSplitUserRealm')) {
        list($remote_user, $realm) = $this->splitUserNameRealm($remote_user);
      }
    }

    $account = NULL;
    if ($remote_user) {
      $this->detailLog
        ->log('SSO raw result is username=@remote_user, (realm=@realm).', [
          '@remote_user' => $remote_user,
          '@realm' => $realm,
          ], 'ldap_sso_auth');
      if ($account = $this->loginRemoteUser($remote_user, $realm)) {
        // User name is valid on remote server.
        user_login_finalize($account);
      }
    }

    // Return valid account or NULL for anonymous.
    return $account;
  }

  /**
   * {@inheritdoc}
   */
  public function loginRemoteUser($remote_user, $realm) {
    if ($this->config->get('ssoRemoteUserStripDomainName')) {
      $remote_user = $this->stripDomainName($remote_user);
    }

    $this->detailLog
      ->log('Continuing SSO login with username=@remote_user, (realm=@realm).', [
        '@remote_user' => $remote_user,
        '@realm' => $realm,
        ], 'ldap_sso_auth'
    );

    return $this->validateUser($remote_user);
  }

  /**
   * {@inheritdoc}
   */
  public function validateUser($remote_user) {
    $this->detailLog->log('Starting validation for SSO user.', [], 'ldap_sso_auth');
    $authentication_successful = $this->validator->processSsoLogin(Html::escape($remote_user));
    if ($authentication_successful) {
      $this->detailLog->log('Remote user has local uid @uid', [
        '@uid' => $this->validator->getDrupalUser()->id(),
        ], 'ldap_sso_auth');
      return $this->validator->getDrupalUser();
    }
    else {
      $this->detailLog->log('Remote user not valid.', [], 'ldap_sso_auth');
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function stripDomainName($remote_user) {
    // Might be in the form of <remote_user>@<domain> or <domain>\<remote_user>.
    $domain = NULL;
    $exploded = preg_split('/[\@\\\\]/', $remote_user);
    if (count($exploded) == 2) {
      if (strpos($remote_user, '@') !== FALSE) {
        $remote_user = $exploded[0];
        $domain = $exploded[1];
      }
      else {
        $domain = $exploded[0];
        $remote_user = $exploded[1];
      }
      $this->detailLog->log('Domain stripped: remote_user=@remote_user, domain=@domain', [
        '@remote_user' => $remote_user,
        '@domain' => $domain,
        ], 'ldap_sso_auth');
    }
    return $remote_user;
  }

  /**
   * {@inheritdoc}
   */
  public function splitUserNameRealm($remote_user) {
    $realm = NULL;
    $domainMatch = preg_match('/^([A-Za-z0-9_\-\.]+)@([A-Za-z0-9_\-.]+)$/', $remote_user, $matches);
    if ($remote_user && $domainMatch) {
      $remote_user = $matches[1];
      // This can be used later if realms is ever supported properly.
      $realm = $matches[2];
    }
    return [$remote_user, $realm];
  }

  /**
   * {@inheritdoc}
   */
  public function checkExcludePath($path = FALSE) {

    $result = FALSE;
    if ($path) {
      // don't derive.
    }
    elseif ($this->request->server->get('PHP_SELF') == '/index.php') {
      $path = $this->request->getPathInfo();
    }
    else {
      // cron.php, etc.
      $path = ltrim($this->request->server->get('PHP_SELF'), '/');
    }

    if (in_array($path, $this->defaultPathsToExclude())) {
      return TRUE;
    }

    if (is_array($this->config->get('ssoExcludedHosts'))) {
      $host = $this->request->server->get('SERVER_NAME');
      foreach ($this->config->get('ssoExcludedHosts') as $host_to_check) {
        if ($host_to_check == $host) {
          return TRUE;
        }
      }
    }

    if ($this->config->get('ssoExcludedPaths')) {
      $patterns = implode("\r\n", $this->config->get('ssoExcludedPaths'));
      if ($patterns) {
        if (function_exists('drupal_get_path_alias')) {
          $path = drupal_get_path_alias($path);
        }
        $path = mb_strtolower($path);

        // Replacements for newlines, asterisks, and the <front> placeholder.
        $to_replace = [
          '/(\r\n?|\n)/',
          '/\\\\\*/',
          '/(^|\|)\\\\<front\\\\>($|\|)/',
        ];
        $replacements = [
          '|',
          '.*',
          '\1' . preg_quote($this->frontpage, '/') . '\2',
        ];
        $patterns_quoted = preg_quote($patterns, '/');
        $regex = '/^(' . preg_replace($to_replace, $replacements, $patterns_quoted) . ')$/';
        $result = (bool) preg_match($regex, $path);
      }
    }

    return $result;
  }

  /**
   * {@inheritdoc}
   */
  public function defaultPathsToExclude() {
    return [
      '/admin/config/search/clean-urls/check',
      '/user/login/sso',
      '/user/login',
      '/user/logout',
    ];
  }

}
