<?php

use dokuwiki\plugin\aclplusregex\test\TestAction;

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

        $pattern = $act->patternToRegexGroup($pattern);
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

    public function providerLoadACLRules()
    {
        return [
            [ // user rule only for a J user
              'john',
              ['foo'],
              ['users:j:john:**' => 16],
            ],
            [ // user rule only for a non-J user
              'harry',
              ['foo'],
              ['users:j:harry:**' => 4],
            ],
            [ // J-User with a matching group
              'john',
              ['12345-doku-l2'],
              [
                  'users:j:john:**' => 16,
                  'kunden:12345:intern:**' => 0,
                  'kunden:12345:intern' => 0,
                  'kunden:12345:**' => 2,
              ],
            ],
            [ // J-User with two matching groups that result in overlapping rules
              'john',
              ['12345-doku-l2', '12345-doku-l3'],
              [
                  'users:j:john:**' => 16,
                  'kunden:12345:intern:**' => 0,
                  'kunden:12345:intern' => 0,
                  'kunden:12345:**' => 16,
              ],
            ],
        ];
    }

    /**
     * Test loading ACL rules for different users
     *
     * Testing happens against _test/conf/aclplusregex.conf
     *
     * @dataProvider providerLoadACLRules
     * @param string $user
     * @param string[] $groups
     * @param array $expect
     */
    public function testLoadACLRules($user, $groups, $expect)
    {
        $act = new TestAction();
        $this->assertEquals($expect, $act->loadACLRules($user, $groups));
    }

    /**
     * Test that rules are sorted correctly
     */
    public function testSortRules()
    {
        $act = new TestAction();

        $this->assertEquals(
            [
                'this:has:three:four' => 1,
                'this:has:three' => 1,
                'aaaaaaaa:one' => 1,
                'this:twoverylongthing' => 1,
                'same:foo' => 1,
                'same:*' => 1,
                'same:**' => 1,
                'aa' => 1,
                'zz' => 1,
            ],
            $act->sortRules([
                'this:has:three' => 1,
                'this:twoverylongthing' => 1,
                'this:has:three:four' => 1,
                'same:**' => 1,
                'same:*' => 1,
                'same:foo' => 1,
                'aaaaaaaa:one' => 1,
                'zz' => 1,
                'aa' => 1,
            ])
        );
    }
}
