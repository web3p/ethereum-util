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

    /**
     * testStripZero
     * 
     * @return void
     */
    public function testStripZero()
    {
        $util = new Util;

        $this->assertEquals('1234', $util->stripZero('0x1234'));
        $this->assertEquals('1234', $util->stripZero('1234'));
    }

    /**
     * testIsHex
     * 
     * @return void
     */
    public function testIsHex()
    {
        $util = new Util;

        $this->assertTrue($util->isHex('1234'));
        $this->assertTrue($util->isHex('0x1234'));
        $this->assertFalse($util->isHex('hello world'));
    }

    /**
     * testPublicKeyToAddress
     * 
     * @return void
     */
    public function testPublicKeyToAddress()
    {
        $util = new Util;

        $this->assertEquals('0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f', $util->publicKeyToAddress('044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a'));
        $this->assertEquals('0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f', $util->publicKeyToAddress('0x044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a'));
    }
}