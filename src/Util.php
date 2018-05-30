<?php

/**
 * This file is part of ethereum-util package.
 * 
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 * 
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Web3p\EthereumUtil;

use InvalidArgumentException;
use RuntimeException;
use kornrunner\Keccak;
use Elliptic\EC;
use Elliptic\EC\KeyPair;

class Util
{
    /**
     * SHA3_NULL_HASH
     * 
     * @const string
     */
    const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    /**
     * secp256k1
     * 
     * @var \Elliptic\EC
     */
    protected $secp256k1;

    /**
     * construct
     * 
     * @return void
     */
    public function __construct()
    {
        $this->secp256k1 = new EC('secp256k1');
    }

    /**
     * get
     * 
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        $method = 'get' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], []);
        }
        return false;
    }

    /**
     * set
     * 
     * @param string $name
     * @param mixed $value
     * @return mixed
     */
    public function __set($name, $value)
    {
        $method = 'set' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], [$value]);
        }
        return false;
    }

    /**
     * sha3
     * keccak256
     * 
     * @param string $value
     * @return string
     */
    public function sha3(string $value)
    {
        $hash = Keccak::hash($value, 256);

        if ($hash === $this::SHA3_NULL_HASH) {
            return null;
        }
        return $hash;
    }

    /**
     * isZeroPrefixed
     * 
     * @param string $value
     * @return bool
     */
    public function isZeroPrefixed(string $value)
    {
        return (strpos($value, '0x') === 0);
    }

    /**
     * stripZero
     * 
     * @param string $value
     * @return string
     */
    public function stripZero(string $value)
    {
        if ($this->isZeroPrefixed($value)) {
            $count = 1;
            return str_replace('0x', '', $value, $count);
        }
        return $value;
    }

    /**
     * isHex
     * 
     * @param string $value
     * @return bool
     */
    public function isHex(string $value)
    {
        return (is_string($value) && preg_match('/^(0x)?[a-f0-9]+$/', $value) === 1);
    }
}