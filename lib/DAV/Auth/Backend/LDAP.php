<?php

namespace Sabre\DAV\Auth\Backend;

/**
 * This is an authentication backend that uses ldap.
 *
 * @copyright Copyright (C) fruux GmbH (https://fruux.com/)
 * @author Michael Niewöhner (foss@mniewoehner.de)
 * @author rosali (https://github.com/rosali)
 * @author Evert Pot (http://evertpot.com/)
 * @license http://sabre.io/license/ Modified BSD License
 */
class LDAP extends AbstractBasic
{
    /**
     * LDAP server uri.
     * e.g. ldaps://ldap.example.org
     *
     * @var string
     */
    protected $ldap_uri;

    /*
     * LDAP dn pattern for binding
     *
     * %u   - gets replaced by full username
     * %U   - gets replaced by user part when the
     *        username is an email address
     * %d   - gets replaced by domain part when the
     *        username is an email address
     * %1-9 - gets replaced by parts of the the domain
     *        split by '.' in reverse order
     *        mail.example.org: %1 = org, %2 = example, %3 = mail
     *
     * @var string
     */
    protected $ldap_dn;

    /*
     * LDAP attribute to use for name
     *
     * @var string
     */
    protected $ldap_cn;

    /*
     * LDAP attribute used for mail
     *
     * @var string
     */
    protected $ldap_mail;

    /**
     * Creates the backend object.
     *
     * @param string $ldap_uri
     * @param string $ldap_dn
     * @param string $ldap_cn
     * @param string $ldap_mail
     *
     */
    public function __construct($ldap_uri, $ldap_dn = 'mail=%u', $ldap_cn = 'cn', $ldap_mail = 'mail')
    {
        $this->ldap_uri  = $ldap_uri;
        $this->ldap_dn   = $ldap_dn;
        $this->ldap_cn   = $ldap_cn;
        $this->ldap_mail = $ldap_mail;
    }

    /**
     * Connects to an LDAP server and tries to authenticate.
     *
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    protected function ldapOpen($username, $password)
    {
        $conn = ldap_connect($ldap_uri);
        if(!$conn)
            return false;
        if(!ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3))
            return false;

        $success = false;

        $user_split = explode('@', $username, 2);
        $ldap_user = $user_split[0];
        $ldap_domain = $user_split[1];
        $domain_split = array_reverse(explode('.', $ldap_domain));

        $dn = str_replace('%u', $username, $ldap_dn);
        $dn = str_replace('%U', $ldap_user, $dn);
        if (count($user_split) > 1)
            $dn = str_replace('%d', $ldap_domain, $dn);
        for($i = 1; $i <= count($domain_split) and $i <= 9; $i++)
            $dn = str_replace('%' . $i, $domain_split[$i - 1], $dn);

        try {
            $bind = ldap_bind($conn, $dn, $password);
            if ($bind) {
                $success = true;
            }
        } catch (\ErrorException $e) {
            error_log($e->getMessage());
            error_log(ldap_error($conn));
        }

        ldap_close($ldap);

        return $success;
    }

    /**
     * Validates a username and password by trying to authenticate against LDAP.
     *
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    protected function validateUserPass($username, $password)
    {
        return $this->ldapOpen($username, $password);
    }
}
