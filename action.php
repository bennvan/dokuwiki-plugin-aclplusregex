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
        $controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'handle_acl');

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
                $extraLines = array_merge($extraLines, $this->match($pattern, $user, [$user], $line));
            } elseif ($pattern[0] === '@') {
                $extraLines = array_merge($extraLines, $this->match($pattern, $user, $groups, $line));
            }
        }

        return array_filter($extraLines);
    }

    /**
     * Returns as many rules as there are pattern matches
     *
     * @param string $pattern   Regex from config
     * @param string $user      Current user's name
     * @param array $properties User properties to check: username or groups
     * @param string $line      Config line
     * @return array
     */
    protected function match($pattern, $user, $properties, $line)
    {
        $extras = [];

        // prepare the line to be added to ACLs if pattern actually matches: substitute username for the pattern already
        $preparedLine = str_replace($pattern, auth_nameencode($user), $line);

        foreach ($properties as $property) {
            $cnt = 0;
            // build an extra ACL rule by replacing the placeholders/backreferences in prepared line with captured groups
            $extra = preg_replace(
                '!' . $pattern . '!',
                $preparedLine,
                $property,
                1,
                $cnt
            );
            // add the rule if anything was replaced
            if ($cnt > 0) {
                $extras[] = $extra;
            }
        }
        return $extras;
    }
}
