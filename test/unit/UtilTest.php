<?php

namespace Test\Unit;

use Test\TestCase;
use Web3p\EthereumUtil\Util;

class UtilTest extends TestCase
{
    /**
     * testSha3
     * 
     * @return void
     */
    public function testSha3()
    {
        $util = new Util;

        $this->assertNull($util->sha3(''));
        $this->assertEquals('47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad', $util->sha3('hello world'));
    }

    /**
     * testIsZeroPrefixed
     * 
     * @return void
     */
    public function testIsZeroPrefixed()
    {
        $util = new Util;

        $this->assertTrue($util->isZeroPrefixed('0x1234'));
        $this->assertFalse($util->isZeroPrefixed('1234'));
    }
}