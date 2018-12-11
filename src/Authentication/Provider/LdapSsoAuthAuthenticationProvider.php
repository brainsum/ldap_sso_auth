<?php

namespace Drupal\ldap_sso_auth\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\ldap_sso_auth\LdapSsoAuthAuthenticationInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Class LdapSsoAuthAuthenticationProvider.
 */
class LdapSsoAuthAuthenticationProvider implements AuthenticationProviderInterface {

  /**
   * The request.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $LdapSsoAuth;

  /**
   * Constructs a LDAP SSO Auth authentication provider object.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface
   *   The service injection container.
   */
  public function __construct(LdapSsoAuthAuthenticationInterface $ldap_sso_auth_auth) {
    $this->LdapSsoAuth = $ldap_sso_auth_auth;
  }

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
  public function applies(Request $request) {
    return $this->LdapSsoAuth->applies($request);
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    return $this->LdapSsoAuth->authenticate($request);
  }

  /**
   * {@inheritdoc}
   */
  public function cleanup(Request $request) {}

  /**
   * {@inheritdoc}
   */
  public function handleException(GetResponseForExceptionEvent $event) {
    $exception = $event->getException();
    if ($exception instanceof AccessDeniedHttpException) {
      $event->setException(
        new UnauthorizedHttpException('Invalid consumer origin.', $exception)
      );
      return TRUE;
    }
    return FALSE;
  }

}
