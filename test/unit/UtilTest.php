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

    /**
     * testPrivateKeyToPublicKey
     * 
     * @return void
     */
    public function testPrivateKeyToPublicKey()
    {
        $util = new Util;

        $this->assertEquals('0x044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a', $util->privateKeyToPublicKey('0x4646464646464646464646464646464646464646464646464646464646464646'));
        $this->assertEquals('0x044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a', $util->privateKeyToPublicKey('4646464646464646464646464646464646464646464646464646464646464646'));
    }

    /**
     * testRecoverPublicKey
     * 
     * @return void
     */
    public function testRecoverPublicKey()
    {
        $util = new Util;

        $this->assertEquals('0x044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a', $util->recoverPublicKey('0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53', '0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276', '0x67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83', 0));
        $this->assertEquals('0x044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a', $util->recoverPublicKey('daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53', '28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276', '67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83', 0));
    }

    /**
     * testEcsign
     * 
     * @return void
     */
    public function testEcsign()
    {
        $util = new Util;
        $signature = $util->ecsign('0x4646464646464646464646464646464646464646464646464646464646464646', 'daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53');

        // EIP155 test data
        $this->assertEquals('28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276', $signature->r->toString(16));
        $this->assertEquals('67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83', $signature->s->toString(16));
        $this->assertEquals(35, $signature->recoveryParam);
    }

    /**
     * testHashPersonalMessage
     * 
     * @return void
     */
    public function testHashPersonalMessage()
    {
        $util = new Util;
        $hashedMessage = $util->hashPersonalMessage('Hello world');

        $this->assertEquals('8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede', $hashedMessage);
    }
}