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
     *      [expected new ACLs]
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
                ],
                [
                    'customers:$1:*	@(\d{6}).*	4',
                    'customers:$1:secret:*	@(\d{6}).*	0',
                ],
                [
                    'customers:987654:*	@987654%5fmatching	4',
                    'customers:987654:secret:*	@987654%5fmatching	0',
                ],
            ],
            [
                '123456_user',
                [
                    'non-matching-group',
                ],
                [
                    'customers:$1:*	(\d{6}).*	8',
                ],
                [
                    'customers:123456:*	123456%5fuser	8',
                ],
            ],
        ];
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
        /** @var action_plugin_aclplusregex $act */
        $act = plugin_load('action', 'aclplusregex');

        $actual = $act->extendAcl($user, $groups, $extraAcl);

        $this->assertEquals($expected, $actual);
    }
}
