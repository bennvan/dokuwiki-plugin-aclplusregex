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

    /** @var int used to uniquely name capture groups */
    protected $counter = 0;

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
     * Apply our own acl checking mechanism
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
            $this->ruleCache[$user] = $this->rulesToRegex($this->loadACLRules($user, $groups));
        }

        // apply the rules and use the resulting permission
        $previous = $event->result ?: AUTH_NONE;
        $permisson = $this->evaluateRegex($this->ruleCache[$user], $id);
        if ($permisson !== false) {
            $event->result = max($previous, $permisson);

            // in BEFORE mode also prevent additional checks
            if ($mode === 'BEFORE') {
                $event->preventDefault();
            }
        }
    }

    /**
     * Applies the given regular expression to the ID and returns the resulting permission
     *
     * Important: there's a difference between a return value of 0 = AUTH_NONE and false = no match found
     *
     * @param string $regex
     * @param string $id
     * @return false|int
     */
    protected function evaluateRegex($regex, $id)
    {
        if (!preg_match($regex, $id, $matches)) {
            // no rule matches
            return false;
        }

        // now figure out which group matched
        foreach ($matches as $key => $match) {
            if (!is_string($key)) continue; // we only care bout named groups
            if ($match === '') continue; // this one didn't match

            list(, $perm) = explode('x', $key); // the part after the x is our permission
            return (int)$perm;
        }

        return false; //shouldn't never be reached
    }

    /**
     * Load the custom ACL regexes for the given user
     *
     * @param string $user
     * @param string[] $groups
     * @return array
     */
    protected function loadACLRules($user, $groups)
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
     * Convert the list of rules to a single regular expression
     *
     * @param array $rules
     * @return string
     */
    protected function rulesToRegex($rules)
    {
        $reGroup = [];
        foreach ($rules as $rule => $perm) {
            $reGroup[] = $this->patternToRegexGroup($rule, $perm);
        }

        return '/^(' . join('|', $reGroup) . ')$/';
    }

    /**
     * Combines the user and group info in prefixed entities
     *
     * @param string $user
     * @param string[] $groups
     * @return array
     */
    protected function createUserGroupEntities($user, $groups)
    {
        array_walk($groups, function (&$gr) {
            $gr = '@' . $gr;
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
    protected function getIDPatterns($entities, $id, $pattern)
    {
        $result = [];

        foreach ($entities as $entity) {
            $check = "$id\n$entity";
            $cnt = 0;

            // pattern not starting with @ should only match users
            if ($pattern[0] !== '@') {
                $pattern = '(?!@)' . $pattern;
            }

            // this does a match on the pattern and replaces backreferences at the same time
            $match = preg_replace("/^$pattern$/m", $check, $entity, 1, $cnt);
            if ($cnt > 0) {
                $result[] = $this->cleanID(explode("\n", $match)[0]);
            }
        }

        return $result;
    }

    /**
     * Replaces * and ** in IDs with their proper regex equivalents and returns a named
     * group which's name encodes the permission
     *
     * @param string $idpattern
     * @param int $perm
     * @return string
     */
    protected function patternToRegexGroup($idpattern, $perm)
    {
        $idpattern = strtr(
            $idpattern,
            [
                '**' => self::STARS,
                '*' => self::STAR,
            ]
        );

        // we abuse named groups to know the for the rule later
        $name = 'g' . ($this->counter++) . 'x' . $perm;

        return '(?<' . $name . '>' . $idpattern . ')';
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
            $config[] = array_map('rawurldecode', preg_split('/[ \t]+/', $line, 3)); // config is encoded
        }

        return $config;
    }

    /**
     * Sort the given rules so that the most significant ones come first
     *
     * @param array $rules
     * @return array (rule => perm)
     */
    protected function sortRules($rules)
    {
        uksort($rules, function ($a, $b) {
            $partsA = explode(':', $a);
            $countA = count($partsA);
            $partsB = explode(':', $b);
            $countB = count($partsB);

            for ($i = 0; $i < max($countA, $countB); $i++) {
                // fill up missing parts with low prio markers
                $partA = $partsA[$i] ?: '**';
                $partB = $partsB[$i] ?: '**';

                // if both parts are the same, move on
                if ($partA === $partB) continue;

                // greedy placeholders go last
                if ($partA === '**') return 1;
                if ($partB === '**') return -1;

                // nongreedy placeholders go second last
                if ($partA === '*') return 1;
                if ($partB === '*') return -1;

                // just compare alphabetically
                return strcmp($a, $b);
            }

            // probably never reached
            return strcmp($a, $b);
        });

        return $rules;
    }

    /**
     * Applies cleanID to each separate part of the ID
     *
     * keeps * and ** placeholders
     *
     * @param string $id
     * @return string
     * @see \cleanID()
     */
    protected function cleanID($id)
    {
        $parts = explode(':', $id);
        $count = count($parts);
        for ($i = 0; $i < $count; $i++) {
            if ($parts[$i] == '**') continue;
            if ($parts[$i] == '*') continue;
            $parts[$i] = cleanID($parts[$i]);
            if ($parts[$i] === '') unset($parts[$i]);
        }
        return join(':', $parts);
    }
}
