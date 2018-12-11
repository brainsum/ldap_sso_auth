<?php

namespace Drupal\ldap_sso_auth\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Url;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_authentication\Helper\LdapAuthenticationConfiguration;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides the configuration form SSO under LDAP configuration.
 */
class LdapSsoAuthAdminForm extends ConfigFormBase {

  /**
   * The server factory service.
   *
   * @var \Drupal\ldap_servers\ServerFactory
   */
  protected $serverFactory;
  protected $storage;

  /**
   * LdapSettingsForm constructor.
   */
  public function __construct(ConfigFactoryInterface $config_factory, ServerFactory $serverFactory, EntityTypeManager $entity_type_manager) {
    parent::__construct($config_factory);
    $this->serverFactory = $serverFactory;
    $this->storage = $entity_type_manager->getStorage('ldap_server');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('ldap.servers'),
      $container->get('entity_type.manager')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_sso_auth_admin_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['ldap_sso_auth.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('ldap_sso_auth.settings');

    $form['information'] = [
      '#type' => 'markup',
      '#markup' => $this->t('<h2>Single sign-on (SSO)</h2><p>Single sign-on enables users of this site to be authenticated by visiting the URL /user/login/sso, or automatically if selected below. Please review the README file for more information.</p>', [
        '@link' => Url::fromRoute('system.modules_list')->toString(),
      ]),
    ];

    $form['seamlessLogin'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Turn on automated single sign-on'),
      '#description' => $this->t('This requires that you have operational NTLM or Kerberos authentication turned on for at least the path /user/login/sso (enabling it for the entire host works too).'),
      '#default_value' => $config->get('seamlessLogin'),
    ];

    $form['ssoSplitUserRealm'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Split user name and realm'),
      '#description' => $this->t("If your users are shown as user@realm, you need to enable this. <br><strong>This is the default for mod_auth_kerb but not mod_auth_sspi.</strong>"),
      '#default_value' => $config->get('ssoSplitUserRealm'),
    ];

    $form['ssoRemoteUserStripDomainName'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Strip REMOTE_USER of domain name'),
      '#description' => $this->t('Use this if you get users in the form of user@realm via SSO and also want to authenticate manually without a realm and avoid duplicate or conflicting accounts.'),
      '#default_value' => $config->get('ssoRemoteUserStripDomainName'),
    ];

    //$form['cookieExpire'] = [
    //  '#type' => 'checkbox',
    //  '#title' => $this->t('Invalidate SSO cookie immediately'),
    //  '#description' => $this->t("Turn this on if you want to make it possible for users to log right back in after logging out with automated single sign-on.<br>This is off by default and set to a session cookie so opening a browser clears the setting."),
    //  '#default_value' => $config->get('cookieExpire'),
    //];

    $form['ssoVariable'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Server variable containing the user'),
      '#description' => $this->t('This is usually REMOTE_USER or REDIRECT_REMOTE_USER.'),
      '#default_value' => $config->get('ssoVariable'),
    ];

    $form['ssoExcludedPaths'] = [
      '#type' => 'textarea',
      '#title' => $this->t('SSO Excluded Paths'),
      '#description' => $this->t("Common paths to exclude from SSO are for example cron.php.<br>This module already excludes some system paths, such as /user/login.<br>Specify pages by using their paths. Enter one path per line. The '*' character is a wildcard.<br>Example paths are %blog for the blog page and %blog-wildcard for all pages below it. %front is the front page.",
        ['%blog' => 'blog', '%blog-wildcard' => 'blog/*', '%front' => '<front>']),
      '#default_value' => LdapAuthenticationConfiguration::arrayToLines($config->get('ssoExcludedPaths')),
    ];

    $form['ssoExcludedHosts'] = [
      '#type' => 'textarea',
      '#title' => $this->t('SSO Excluded Hosts'),
      '#description' => $this->t('If your site is accessible via multiple hostnames, you may only want
        the LDAP SSO module to authenticate against some of them.<br>Enter one host per line.'),
      '#default_value' => LdapAuthenticationConfiguration::arrayToLines($config->get('ssoExcludedHosts')),
    ];
 
    $form['login'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Login customization'),
    ];
    
    $form['login']['redirectOnLogout'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Redirect users on logout'),
      '#description' => $this->t('Recommended to be set for most sites to a non-SSO path. Can cause issues with immediate cookie invalidation and automated SSO.'),
      '#default_value' => $config->get('redirectOnLogout'),
    ];
    
    $form['login']['logoutRedirectPath'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Logout redirect path'),
      '#description' => $this->t('An internal Drupal path that users will be redirected to on logout'),
      '#default_value' => $config->get('logoutRedirectPath'),
      '#required' => FALSE,
      '#states' => [
        'visible' => [
          'input[name="redirectOnLogout"]' => ['checked' => TRUE],
        ],
        'required' => [
          'input[name="redirectOnLogout"]' => ['checked' => TRUE],
        ],
      ],
    ];
    
    $form['login']['enableLoginConfirmationMessage'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Show a confirmation message on successful login'),
      '#default_value' => $config->get('enableLoginConfirmationMessage'),
    ];
    
    $form['submit'] = [
      '#type' => 'submit',
      '#value' => 'Save',
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $query_result = $this->storage
      ->getQuery()
      ->condition('status', 1)
      ->execute();
    $enabled_servers = $this->storage->loadMultiple($query_result);
    /* @var \Drupal\ldap_servers\Entity\Server $server */
    foreach ($enabled_servers as $server) {
      if ($server->get('bind_method') == 'user' || $server->get('bind_method') == 'anon_user') {
        $form_state->setErrorByName('ssoEnabled', $this->t("Single sign-on is not valid with the server %sid because that server configuration uses %bind_method. Since the user's credentials are never available to this module with single sign-on enabled, there is no way for the ldap module to bind to the ldap server with credentials.",
          [
            '%sid' => $server->id(),
            '%bind_method' => $server->getFormattedBind(),
          ]
        ));
      }
    }

    if ($form_state->getValue('redirectOnLogout')) {
      if ($form_state->getValue('logoutRedirectPath') == '') {
        $form_state->setErrorByName('logoutRedirectPath', $this->t('Redirect logout path cannot be blank'));
      }

      try {
        Url::fromUserInput($form_state->getValue('logoutRedirectPath'));
      }
      catch (\InvalidArgumentException $ex) {
        $form_state->setErrorByName('logoutRedirectPath', $this->t('The path you entered for Redirect logout path is not a valid internal path, internal paths should start with: /, ? or #'));
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $this->config('ldap_sso_auth.settings')
      ->set('ssoExcludedPaths', LdapAuthenticationConfiguration::linesToArray($values['ssoExcludedPaths']))
      ->set('ssoExcludedHosts', LdapAuthenticationConfiguration::linesToArray($values['ssoExcludedHosts']))
      ->set('seamlessLogin', $values['seamlessLogin'])
      ->set('ssoSplitUserRealm', $values['ssoSplitUserRealm'])
      ->set('ssoRemoteUserStripDomainName', $values['ssoRemoteUserStripDomainName'])
      //->set('cookieExpire', $values['cookieExpire'])
      ->set('ssoVariable', $values['ssoVariable'])
      ->set('redirectOnLogout', $values['redirectOnLogout'])
      ->set('logoutRedirectPath', $values['logoutRedirectPath'])
      ->set('enableLoginConfirmationMessage', $values['enableLoginConfirmationMessage'])
      ->save();
  }

}
