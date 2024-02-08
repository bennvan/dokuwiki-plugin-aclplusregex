<?php

namespace dokuwiki\plugin\aclplusregex\test;

/**
 * Tests for the aclplusregex plugin
 *
 * @group plugin_aclplusregex
 * @group plugins
 */
class AclTest extends \DokuWikiTest
{
    protected $pluginsEnabled = ['aclplusregex'];

    /**
     * @return array
     * @see testFullChain
     */
    public function providerFullChain()
    {
        return [
            [
                'users:foo:bar',
                'john',
                ['foo', '12345-doku-l1'],
                false,
            ],
            [
                'users:j:john:my:page',
                'john',
                ['foo', '12345-doku-l1'],
                16,
            ],
            [
                'kunden:12345:nosecret',
                'john',
                ['foo', '12345-doku-l1'],
                1,
            ],
            [
                'kunden:12345:intern',
                'john',
                ['foo', '12345-doku-l1'],
                0,
            ],
            [
                'kunden:12345:intern:secret',
                'john',
                ['foo', '12345-doku-l1'],
                0,
            ],
            [
                'kunden:12345:intern:secret',
                'james',
                ['foo', '12345-doku-l1', '12345-doku-intern-l3'],
                16,
            ],
        ];
    }

    /**
     * Run a full check on the result our system should deliver for the given names
     *
     * Testing happens against _test/conf/aclplusregex.conf
     *
     * @dataProvider providerFullChain
     * @param string $id
     * @param string $user
     * @param string[] $groups
     * @param int|false $expected
     */
    public function testFullChain($id, $user, $groups, $expected)
    {
        $act = new TestAction();

        $this->assertSame(
            $expected,
            $act->evaluateRegex(
                $act->rulesToRegex(
                    $act->loadACLRules($user, $groups)
                ),
                $id
            )
        );
    }

    /**
     * @return array
     * @see testFullChainNsRegex
     */
    public function providerFullChainNsRegex()
    {
        return [
            [
                'reg:12345:678:sub',
                'joshua',
                ['foo', '12345-doku-sub-r1'],
                4,
            ],
            [
                'reg:12345:sub-678:sub',
                'joshua',
                ['foo', '12345-doku-bus-sub-r2'],
                16,
            ],
            [
                'reg:12345:sub-678:bus',
                'joshua',
                ['foo', '12345-doku-bus-sub-r2'],
                2,
            ],
            [
                'reg:12345:sub-90:sub',
                'joshua',
                ['foo', '12345-doku-bus-sub-r3'],
                8,
            ],
            [
                'reg:12345:sub-90:bus',
                'joshua',
                ['foo', '12345-doku-bus-sub-r3'],
                1,
            ],
        ];
    }

    /**
     * Run a full check on the result our system should deliver for the given names
     *
     * Testing happens against _test/conf/aclplusregex.conf
     *
     * @dataProvider providerFullChainNsRegex
     * @param string $id
     * @param string $user
     * @param string[] $groups
     * @param int|false $expected
     */
    public function testFullChainNsRegex($id, $user, $groups, $expected)
    {
        $act = new TestAction();

        $this->assertSame(
            $expected,
            $act->evaluateRegex(
                $act->rulesToRegex(
                    $act->loadACLRules($user, $groups)
                ),
                $id
            )
        );
    }

    /**
     * @return array (entities, id, pattern, expected)
     * @see testGetIdPatterns
     */
    public function providerGetIdPatterns()
    {
        $entities = ['user_name', '@987654_matching', '@non-matching-group', '@123456_matching'];

        return [
            [
                $entities,
                'customers:$1:*',
                '@(\d{6})_.*',
                [
                    'customers:987654:*',
                    'customers:123456:*',
                ],
            ],
            [
                $entities,
                'user:$1:**',
                '(.*)',
                [
                    'user:user_name:**',
                ],
            ],
            [
                ['user name'], // clean the space in the name
                'user:$1:**',
                '(.*)',
                [
                    'user:user_name:**',
                ],
            ],
        ];
    }

    /**
     * Test some individual patterns and users
     *
     * @dataProvider providerGetIdPatterns
     */
    public function testGetIdPatterns($entities, $id, $pattern, $expected)
    {
        $act = new TestAction();
        $this->assertEquals($expected, $act->getIDPatterns($entities, $id, $pattern));
    }

    /**
     * @return array (user, groups, expect)
     * @see testLoadACLRules
     */
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
            [ // user rule with a fancy user name
              'Harry Belafonte',
              ['foo'],
              ['users:j:harry_belafonte:**' => 4],
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
     * @return array (rules, expect)
     * @see testSortRules
     */
    public function providerSortRules()
    {
        return [
            [
                [
                    'this:is:longer' => 1,
                    'this:is:longer:even' => 1,
                    'this:short' => 1,
                    'this' => 1,
                ],
                [
                    'this:is:longer:even' => 1,
                    'this:is:longer' => 1,
                    'this:short' => 1,
                    'this' => 1,
                ],
            ],
            [
                [
                    'kunden:12345:intern:**' => 1,
                    'kunden:12345:**' => 1,
                    'kunden:12345:intern' => 1,
                ],
                [
                    'kunden:12345:intern' => 1,
                    'kunden:12345:intern:**' => 1,
                    'kunden:12345:**' => 1,
                ],
            ],
            [
                [
                    'this:has:three' => 1,
                    'this:twoverylongthing' => 1,
                    'this:has:three:four' => 1,
                    'same:**' => 1,
                    'same:*' => 1,
                    'same:foo' => 1,
                    'aaaaaaaa:one' => 1,
                    'zz' => 1,
                    'aa' => 1,
                ],
                [
                    'aa' => 1,
                    'aaaaaaaa:one' => 1,
                    'same:foo' => 1,
                    'same:*' => 1,
                    'same:**' => 1,
                    'this:has:three:four' => 1,
                    'this:has:three' => 1,
                    'this:twoverylongthing' => 1,
                    'zz' => 1,
                ],
            ],
            [
                [
                    'reg:12345:(sub-\d{3}):sub' => 1,
                    'reg:12345:(sub-\d{3}):*' => 1,
                    'reg:12345:sub-678:bus' => 1,
                ],
                [
                    'reg:12345:sub-678:bus' => 1,
                    'reg:12345:(sub-\d{3}):sub' => 1,
                    'reg:12345:(sub-\d{3}):*' => 1,
                ],
            ],
        ];
    }

    /**
     * Test that rules are sorted correctly
     *
     * @dataProvider providerSortRules
     * @param array $rules
     * @param array $expect
     */
    public function testSortRules($rules, $expect)
    {
        $act = new TestAction();

        $this->assertSame(
            $expect,
            $act->sortRules($rules)
        );
    }

    public function testPatternToRegexGroup()
    {
        $acl = new TestAction();

        $this->assertEquals(
            '(?<g0x4>foo:' . TestAction::STARS . ')',
            $acl->patternToRegexGroup('foo:**', 4)
        );

        $this->assertEquals(
            '(?<g1x4>foo:' . TestAction::STAR . ')',
            $acl->patternToRegexGroup('foo:*', 4)
        );

        $this->assertEquals(
            '(?<g2x4>foo:' . TestAction::STAR . ':' . TestAction::STARS . ')',
            $acl->patternToRegexGroup('foo:*:**', 4)
        );

    }
}
