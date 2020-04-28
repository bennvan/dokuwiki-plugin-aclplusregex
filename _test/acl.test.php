<?php

/**
 * Tests for the aclplusregex plugin
 *
 * @group plugin_aclplusregex
 * @group plugins
 */
class helper_plugin_aclplusregex_test extends DokuWikiTest
{
    protected $pluginsEnabled = ['aclplusregex'];

    /**
     * Test data
     * [
     *      user,
     *      [user groups],
     *      [plugin configuration lines],
     *      [expected resulting ACLs]
     * ]
     *
     * @return array
     */
    public function dataACL()
    {
        return [
            [
                'user_name',
                [
                    '987654_matching',
                    'non-matching-group',
                    '123456_matching',
                ],
                [
                    'customers:$1:*	@(\d{6})_.*	4',
                    'customers:$1:secret:*	@(\d{6})_.*	0',
                ],
                [
                    'customers:987654:*	user%5fname	4',
                    'customers:123456:*	user%5fname	4',
                    'customers:987654:secret:*	user%5fname	0',
                    'customers:123456:secret:*	user%5fname	0',
                ],
            ],
            [
                '123456_user',
                [
                    'non-matching-group',
                ],
                [
                    'customers:$1:*	(\d{6})_.*	8',
                ],
                [
                    'customers:123456:*	123456%5fuser	8',
                ],
            ],
        ];
    }

    public function patternIdProvider()
    {
        $entities = ['user_name', '@987654_matching', '@non-matching-group', '@123456_matching'];

        return [
            [
                $entities,
                'customers:$1:*',
                '@(\d{6})_.*',
                [
                    'customers:987654:' . action_plugin_aclplusregex::STAR,
                    'customers:123456:' . action_plugin_aclplusregex::STAR,
                ],
            ],
        ];
    }

    /**
     * @dataProvider patternIdProvider
     */
    public function testGetPatterns($entities, $id, $pattern, $expected)
    {
        /** @var action_plugin_aclplusregex $act */
        $act = plugin_load('action', 'aclplusregex');

        $this->assertEquals($expected, $act->getIDPatterns($entities, $id, $pattern));
    }

    public function idpatternProvider()
    {
        return [
            [
                'foo:bar:*', // pattern
                ['foo:bar:baz'], // matches
                ['foo', 'foo:bar:baz:bang'], // but not
            ],

            [
                'foo:*:bang', // pattern
                ['foo:bar:bang'], // matches
                ['foo', 'foo:bar:baz:bang'], // but not
            ],

            [
                'foo:*:bang:*', // pattern
                ['foo:bar:bang:poff'], // matches
                [
                    'foo',
                    'foo:bar:baz:bang',
                    'foo:bar:bang:poff:huh',
                ], // but not
            ],
        ];
    }

    /**
     * @dataProvider idpatternProvider
     */
    public function testGetIDPatterns($pattern, $matches, $notmatches)
    {
        /** @var action_plugin_aclplusregex $act */
        $act = plugin_load('action', 'aclplusregex');

        $pattern = $act->patternToRegex($pattern);
        $pattern = "/^$pattern$/"; // we anchor our patterns

        foreach ($matches as $match) {
            $this->assertRegExp($pattern, $match);
        }

        foreach ($notmatches as $notmatch) {
            $this->assertNotRegExp($pattern, $notmatch);
        }
    }

    /**
     * Test extending ACLs with regex configuration
     *
     * @dataProvider dataACL
     * @param string $user
     * @param array $groups
     * @param array $extraAcl
     * @param array $expected
     */
    public function testACL($user, $groups, $extraAcl, $expected)
    {
        $this->markTestSkipped('obsolete test, needs cleanup');
        return;

        /** @var action_plugin_aclplusregex $act */
        $act = plugin_load('action', 'aclplusregex');

        $actual = $act->extendAcl($user, $groups, $extraAcl);

        $this->assertEquals($expected, $actual);
    }
}
