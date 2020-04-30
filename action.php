<?php
/**
 * DokuWiki Plugin aclplusregex (Action Component)
 *
 */

class action_plugin_aclplusregex extends DokuWiki_Action_Plugin
{
    const CONFFILE = DOKU_CONF . 'aclplusregex.conf';

    /** @var string Regex for the * placeholder */
    const STAR = '[^:]+';
    /** @var string Regex for the ** placeholder */
    const STARS = '[^:]+(:[^:]+)*';

    /** @var array we store the regexes per user here */
    protected $ruleCache = [];

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller)
    {
        $mode = $this->getConf('run');
        $controller->register_hook('AUTH_ACL_CHECK', $mode, $this, 'handle_acl', $mode);

    }

    /**
     * Manipulates global $AUTH_ACL based on regex in plugin configuration
     * and adds rules if the current user matches a pattern.
     *
     * @param Doku_Event $event event object by reference
     * @param string $mode BEFORE|AFTER
     * @return void
     */
    public function handle_acl(Doku_Event $event, $mode)
    {
        $id = $event->data['id'];
        $user = $event->data['user'];
        $groups = $event->data['groups'];

        if ($user === '') return;

        // use cached user rules or fetch new ones if not available
        if (!isset($this->ruleCache[$user])) {
            $this->ruleCache[$user] = $this->loadACLRules($user, $groups);
        }

        // only apply rules that would result in higher permission
        $previous = $event->result ?: AUTH_NONE;
        $rules = array_filter(
            $this->ruleCache[$user],
            function ($key) use ($previous) {
                return $key > $previous;
            },
            ARRAY_FILTER_USE_KEY
        );

        // see if we have a matching rule
        $result = false;
        foreach ($rules as $perm => $rule) {
            if (preg_match($rule, $id)) {
                $result = $perm;
                break;
            }
        }

        // in before mode, abort checking if we found any result
        if ($mode === 'BEFORE' && $result !== false) {
            $event->preventDefault();
        }

        $event->result = $result;
    }

    /**
     * Load the custom ACL regexes for the given user
     *
     * @param string $user
     * @param string $groups
     * @return array
     */
    public function loadACLRules($user, $groups)
    {
        $entities = $this->createUserGroupEntities($user, $groups);
        $config = $this->getConfiguration();

        // get all rules that apply to the user and their groups
        $rules = [];
        foreach ($config as list($id, $pattern, $perm)) {
            $perm = (int)$perm;
            $rules[$perm] = $this->getIDPatterns($entities, $id, $pattern);
        }

        // make a single regex per permission
        foreach ($rules as $perm => $list) {
            $rules[$perm] = '/^(' . join('|', $list) . '$/';
        }

        krsort($rules);
        return $rules;
    }

    /**
     * Generates a list of encoded entities as they would be used in the ACL config file
     *
     * @param $user
     * @param $groups
     * @return array
     */
    public function createUserGroupEntities($user, $groups)
    {
        $user = auth_nameencode($user);
        array_walk($groups, function (&$gr) {
            $gr = '@' . auth_nameencode($gr);
        });
        $entities = (array)$groups;
        $entities[] = $user;
        return $entities;
    }

    /**
     * Returns all ID patterns that match the given user entities
     *
     * @param string[] $entities List of username and groups
     * @param string $id The pageID part of the config rule
     * @param string $pattern The user pattern part of the config rule
     * @return string[]
     */
    public function getIDPatterns($entities, $id, $pattern)
    {
        $result = [];

        foreach ($entities as $entity) {
            $check = "$id\n$entity";
            $cnt = 0;

            $match = preg_replace("/$pattern/s", $check, $entity, 1, $cnt);
            if ($cnt > 0) {
                $result[] = $this->patternToRegex(explode("\n", $match)[0]);
            }
        }

        return $result;
    }

    /**
     * Replaces * and ** in IDs with their proper regex equivalents
     *
     * @param string $idpattern
     * @return string
     */
    public function patternToRegex($idpattern)
    {
        return str_replace(
            ['**', '*'],
            [self::STARS, self::STAR],
            $idpattern
        );
    }

    /**
     * @return string[][] a list of (id, pattern, perm)
     */
    protected function getConfiguration()
    {
        if (!is_file(self::CONFFILE)) {
            msg(
                'Configuration file for plugin aclplusregex was not found! Your ACLs might be incorrect.',
                -1, '', '', MSG_ADMINS_ONLY
            );
            return [];
        }

        $config = [];
        $file = file(self::CONFFILE);
        foreach ($file as $line) {
            $line = preg_replace('/#.*$/', '', $line); // strip comments
            $line = trim($line);
            if ($line === '') continue;
            $config[] = preg_split('/[ \t]+/', $line, 3);
        }

        return $config;
    }

}
