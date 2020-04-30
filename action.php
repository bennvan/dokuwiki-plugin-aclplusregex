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
     * @param string[] $groups
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
            $patterns = $this->getIDPatterns($entities, $id, $pattern);
            foreach ($patterns as $pattern) {
                // for the exactly same pattern, we only keep the highest permission
                $rules[$pattern] = max($rules[$pattern] ?: AUTH_NONE, $perm);
            }

        }

        // sort rules by significance
        $rules = $this->sortRules($rules);

        return $rules;
    }

    /**
     * Generates a list of encoded entities as they would be used in the ACL config file
     *
     * @param string $user
     * @param string[] $groups
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
        $entities[] = '@ALL'; // everyone is in this
        return $entities;
    }

    /**
     * Returns all ID patterns that match the given user/group entities
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

            // pattern not starting with @ should only match users
            if($pattern[0] !== '@') {
                $pattern = '(?!@)'.$pattern;
            }

            $match = preg_replace("/^$pattern$/m", $check, $entity, 1, $cnt);
            if ($cnt > 0) {
                $result[] = explode("\n", $match)[0];
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
        if (!is_file(static::CONFFILE)) {
            msg(
                'Configuration file for plugin aclplusregex was not found! Your ACLs might be incorrect.',
                -1, '', '', MSG_ADMINS_ONLY
            );
            return [];
        }

        $config = [];
        $file = file(static::CONFFILE);
        foreach ($file as $line) {
            $line = preg_replace('/#.*$/', '', $line); // strip comments
            $line = trim($line);
            if ($line === '') continue;
            $config[] = preg_split('/[ \t]+/', $line, 3);
        }

        return $config;
    }

    /**
     * Sort the given rules so that the most significant ones come first
     *
     * @param array $rules
     * @return array (rule => perm)
     */
    public function sortRules($rules)
    {
        uksort($rules, function ($a, $b) {
            $partsA = explode(':', $a);
            $countA = count($partsA);
            $partsB = explode(':', $b);
            $countB = count($partsB);

            // more namespaces come first
            if ($countA < $countB) {
                return -1;
            } elseif ($countA < $countB) {
                return 1;
            }

            for ($i = 0; $i < $countA; $i++) {
                $partA = $partsA[$i];
                $partB = $partsB[$i];

                // greedy placeholders go last
                if ($partA === '**') return -1;
                if ($partB === '**') return 1;

                // nongreedy placeholders go second last
                if ($partA === '*') return -1;
                if ($partB === '*') return 1;

                // sort by namespace length
                $lenA = utf8_strlen($partA);
                $lenB = utf8_strlen($partB);
                if ($lenA < $lenB) {
                    return -1;
                } elseif ($lenA < $lenB) {
                    return 1;
                }
            }

            return strcmp($a, $b);
        });

        return $rules;
    }
}
