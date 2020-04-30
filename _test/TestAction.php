<?php

namespace dokuwiki\plugin\aclplusregex\test;

/**
 * Class TestAction
 *
 * Makes internal methods public for testing and uses our custom test configuration
 */
class TestAction extends \action_plugin_aclplusregex
{
    const CONFFILE = __DIR__ . '/conf/aclplusregex.conf';

    /** @inheritDoc */
    public function evaluateRegex($regex, $id)
    {
        return parent::evaluateRegex($regex, $id);
    }

    /** @inheritDoc */
    public function rulesToRegex($rules)
    {
        return parent::rulesToRegex($rules);
    }

    /** @inheritDoc */
    public function loadACLRules($user, $groups)
    {
        return parent::loadACLRules($user, $groups);
    }

    /** @inheritDoc */
    public function patternToRegexGroup($idpattern, $perm)
    {
        return parent::patternToRegexGroup($idpattern, $perm);
    }

    /** @inheritDoc */
    public function getIDPatterns($entities, $id, $pattern)
    {
        return parent::getIDPatterns($entities, $id, $pattern);
    }

    /** @inheritDoc */
    public function sortRules($rules)
    {
        return parent::sortRules($rules);
    }

}
