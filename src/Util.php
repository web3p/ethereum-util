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
use phpseclib\Math\BigInteger as BigNumber;
use Elliptic\EC;
use Elliptic\EC\KeyPair;
use Elliptic\EC\Signature;

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
        return (is_string($value) && preg_match('/^(0x)?[a-fA-F0-9]+$/', $value) === 1);
    }

    /**
     * publicKeyToAddress
     * 
     * @param string $publicKey
     * @throws InvalidArgumentException
     * @return string
     */
    public function publicKeyToAddress(string $publicKey)
    {
        if ($this->isHex($publicKey) === false) {
            throw new InvalidArgumentException('Invalid public key format.');
        }
        $publicKey = $this->stripZero($publicKey);

        if (strlen($publicKey) !== 130) {
            throw new InvalidArgumentException('Invalid public key length.');
        }
        return '0x' . substr($this->sha3(substr(hex2bin($publicKey), 1)), 24);
    }

    /**
     * privateKeyToPublicKey
     * 
     * @param string $privateKey
     * @throws InvalidArgumentException
     * @return string
     */
    public function privateKeyToPublicKey(string $privateKey)
    {
        if ($this->isHex($privateKey) === false) {
            throw new InvalidArgumentException('Invalid private key format.');
        }
        $privateKey = $this->stripZero($privateKey);

        if (strlen($privateKey) !== 64) {
            throw new InvalidArgumentException('Invalid private key length.');
        }
        $privateKey = $this->secp256k1->keyFromPrivate($privateKey, 'hex');
        $publicKey = $privateKey->getPublic(false, 'hex');

        return '0x' . $publicKey;
    }

    /**
     * recoverPublicKey
     *
     * @param string $hash
     * @param string $r
     * @param string $s
     * @param int $v
     * @throws InvalidArgumentException
     * @return string
     */
    public function recoverPublicKey(string $hash, string $r, string $s, int $v)
    {
        if ($this->isHex($hash) === false) {
            throw new InvalidArgumentException('Invalid hash format.');
        }
        $hash = $this->stripZero($hash);

        if ($this->isHex($r) === false || $this->isHex($s) === false) {
            throw new InvalidArgumentException('Invalid signature format.');
        }
        $r = $this->stripZero($r);
        $s = $this->stripZero($s);

        if (strlen($r) !== 64 || strlen($s) !== 64) {
            throw new InvalidArgumentException('Invalid signature length.');
        }
        $publicKey = $this->secp256k1->recoverPubKey($hash, [
            'r' => $r,
            's' => $s
        ], $v);
        $publicKey = $publicKey->encode('hex');

        return '0x' . $publicKey;
    }

    /**
     * ecsign
     * 
     * @param string $privateKey
     * @param string $message
     * @throws InvalidArgumentException
     * @return \Elliptic\EC\Signature
     */
    public function ecsign(string $privateKey, string $message)
    {
        if ($this->isHex($privateKey) === false) {
            throw new InvalidArgumentException('Invalid private key format.');
        }
        $privateKeyLength = strlen($this->stripZero($privateKey));

        if ($privateKeyLength % 2 !== 0 && $privateKeyLength !== 64) {
            throw new InvalidArgumentException('Private key length was wrong.');
        }
        $secp256k1 = new EC('secp256k1');
        $privateKey = $secp256k1->keyFromPrivate($privateKey, 'hex');
        $signature = $privateKey->sign($message, [
            'canonical' => true
        ]);
        // Ethereum v is recovery param + 35
        // Or recovery param + 35 + (chain id * 2)
        $signature->recoveryParam += 35;

        return $signature;
    }

    /**
     * hasPersonalMessage
     * 
     * @param string $message
     * @return string
     */
    public function hashPersonalMessage(string $message)
    {
        $prefix = sprintf("\x19Ethereum Signed Message:\n%d", mb_strlen($message));
        return $this->sha3($prefix . $message);
    }

    /**
     * isNegative
     * 
     * @param string
     * @throws InvalidArgumentException
     * @return bool
     */
    public function isNegative(string $value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isNegative function must be string.');
        }
        return (strpos($value, '-') === 0);
    }

    /**
     * toBn
     * Change number or number string to bignumber.
     * 
     * @param BigNumber|string|int $number
     * @throws InvalidArgumentException
     * @return array|\phpseclib\Math\BigInteger
     */
    public function toBn($number)
    {
        if ($number instanceof BigNumber){
            $bn = $number;
        } elseif (is_int($number)) {
            $bn = new BigNumber($number);
        } elseif (is_numeric($number)) {
            $number = (string) $number;

            if ($this->isNegative($number)) {
                $count = 1;
                $number = str_replace('-', '', $number, $count);
                $negative1 = new BigNumber(-1);
            }
            if (strpos($number, '.') > 0) {
                $comps = explode('.', $number);

                if (count($comps) > 2) {
                    throw new InvalidArgumentException('toBn number must be a valid number.');
                }
                $whole = $comps[0];
                $fraction = $comps[1];

                return [
                    new BigNumber($whole),
                    new BigNumber($fraction),
                    strlen($comps[1]),
                    isset($negative1) ? $negative1 : false
                ];
            } else {
                $bn = new BigNumber($number);
            }
            if (isset($negative1)) {
                $bn = $bn->multiply($negative1);
            }
        } elseif (is_string($number)) {
            $number = mb_strtolower($number);

            if ($this->isNegative($number)) {
                $count = 1;
                $number = str_replace('-', '', $number, $count);
                $negative1 = new BigNumber(-1);
            }
            if (empty($number)) {
                $bn = new BigNumber(0);
            } else if ($this->isZeroPrefixed($number) || $this->isHex($number)) {
                $number = $this->stripZero($number);
                $bn = new BigNumber($number, 16);
            } else {
                throw new InvalidArgumentException('toBn number must be valid hex string.');
            }
            if (isset($negative1)) {
                $bn = $bn->multiply($negative1);
            }
        } else {
            throw new InvalidArgumentException('toBn number must be BigNumber, string or int.');
        }
        return $bn;
    }
}