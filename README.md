
LDAP SSO Auth module
---------------------

* Introduction
* Requirements
* Recommended Modules
* Installation
* Configuration
* Maintainers


INTRODUCTION
------------

This LDAP SSO Auth module integrates a Drupal ...

REQUIREMENTS
------------

This module requires:
 * ldap_servers
 * ldap_authentication

Uncommendable enabling Internal Page Cache module.


INSTALLATION
------------

Install the optimizely module as you would normally install a contributed Drupal
module. Visit https://www.drupal.org/node/1897420 for further information.

Install with composer:
composer require drupal/ldap_sso_auth


CONFIGURATION
--------------

    1. Navigate to Administration > People > LDAP servers > LDAP SSO Auth and
       configure as LDAP server needs it..

KNOWN ISSUES
------------

Symptom: Instead of being recreated, user deleted from Drupal receive access denied. Details: when a user is logged in to Drupal, then gets deleted, it's browser still holds the session cookie and on the next request this module will still receive a session object from Drupal with the deleted user's uid. Currently no other check is running so this module will not initiate the LDAP SSO user recreation process, but will not do anything thinking that the user has a valid living session. Workaround: the user should delete cookies or start a new sole incognito window.

MAINTAINERS
-----------

The 8.x-1.x branch was created by:

 * Dudas Jozsef (dj1999) - https://www.drupal.org/u/dj1999

This module was created and sponsored by Brainsum, a drupal development company
in Budapest, Hungary.

 * Brainsum Kft. - https://www.brainsum.com
