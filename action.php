<?php
/**
 * DokuWiki Plugin aclplusregex (Action Component)
 *
 */

class action_plugin_aclplusregex extends DokuWiki_Action_Plugin
{
    const CONFFILE = DOKU_CONF . 'aclplusregex.conf';

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller)
    {
        $controller->register_hook('DOKUWIKI_STARTED', 'AFTER', $this, 'handle_acl');
    }

    /**
     * Manipulates global $AUTH_ACL based on regex in plugin configuration
     * and adds rules if the current user matches a pattern.
     *
     * @param Doku_Event $event event object by reference
     * @param $param
     * @return void
     */
    public function handle_acl(Doku_Event $event, $param)
    {
        if (empty($_SERVER['REMOTE_USER'])) return;

        if (!is_file(self::CONFFILE)) {
            msg('Configuration file for plugin aclplusregex was not found! Your ACLs might be incorrect.');
            return;
        }

        $extraAcl = file(self::CONFFILE);
        global $AUTH_ACL, $USERINFO, $INFO;

        $AUTH_ACL = array_merge(
            $AUTH_ACL,
            $this->extendAcl($_SERVER['REMOTE_USER'], $USERINFO['grps'], $extraAcl)
        );
        // redo auth_quickaclcheck() after manipulating global ACLs
        $INFO = pageinfo();
    }

    /**
     * Returns dynamically adjusted ACL entries if current user matches a pattern in config.
     * Those will be inserted into global $AUTH_ACL used in permission checks.
     *
     * @param string $user
     * @param array $groups
     * @param array $config
     * @return array
     */
    public function extendAcl($user, $groups, $config)
    {
        $extraLines = [];

        // format names for coming comparisons
        array_walk($groups, function (&$gr) {
            $gr = '@' . $gr;
        });

        foreach($config as $line) {
            $line = trim($line);
            if (empty($line) || ($line[0] == '#')) continue; // skip blank lines & comments
            list($id, $pattern, $perm) = preg_split('/[ \t]+/', $line, 3);

            if ($pattern[0] !== '@') {
                $extraLines[] = $this->match($pattern, $user, [$user], $line);
            } elseif ($pattern[0] === '@') {
                $extraLines[] = $this->match($pattern, $user, $groups, $line);
            }
        }

        return array_filter($extraLines);
    }

    /**
     * One match per config line is enough, more rules would be redundant.
     *
     * @param string $pattern
     * @param string $user
     * @param array $subjects
     * @param string $line
     * @return string
     */
    protected function match($pattern, $user, $subjects, $line)
    {
        foreach ($subjects as $subject) {
            $cnt = 0;
            $extra = preg_replace(
                '!' . $pattern . '!',
                str_replace($pattern, auth_nameencode($user), $line), // set permissions for the user, never the group
                $subject,
                1,
                $cnt
            );
            if ($cnt > 0) {
                return $extra;
            }
        }
        return '';
    }
}
