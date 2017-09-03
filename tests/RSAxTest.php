<?php

use RSAx\RSAx;
use \PHPUnit\Framework\TestCase;

class RSAxTest extends TestCase
{
    private $privateKey;
    private $publicKey;

    private $config = [
        'digest_alg' => 'sha512',
        'private_key_bits' => 4096,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    private $password = '123';

    private $privateKeyPath = '/fixtures/private.key';
    private $publicKeyPath = '/fixtures/public.key';
    private $passwordPath = '/fixtures/pass.txt';

    public function setUp()
    {
        $rsa = new RSAx();
        $rsa->generate($this->config, $this->password);
        $this->privateKey = $rsa->getPrivateKey();
        $this->publicKey = $rsa->getPublicKey();
    }

    public function testEncryptDecrypt()
    {
        $rsa = new RSAx($this->publicKey, $this->privateKey, $this->password);
        $data = 'hello';
        $encrypted = $rsa->encrypt($data);
        $decrypted = $rsa->decrypt($encrypted);
        $this->assertEquals($decrypted, $data);
    }

    public function testEncryptDecryptBase64()
    {
        $rsa = new RSAx($this->publicKey, $this->privateKey, $this->password);
        $data = 'hello';
        $encrypted = $rsa->base64Encrypt($data);
        $decrypted = $rsa->base64Decrypt($encrypted);
        $this->assertEquals($decrypted, $data);
    }

    public function testEncryptDecryptWithFile()
    {
        $rsa = new RSAx(
            __DIR__ . $this->publicKeyPath,
            __DIR__ . $this->privateKeyPath,
            file_get_contents(__DIR__ . $this->passwordPath)
        );
        $data = 'hello';
        $encrypted = $rsa->encrypt($data);
        $decrypted = $rsa->decrypt($encrypted);
        $this->assertEquals($decrypted, $data);
    }

    public function testEncryptDecryptBase64WithFile()
    {
        $rsa = new RSAx(
            __DIR__ . $this->publicKeyPath,
            __DIR__ . $this->privateKeyPath,
            file_get_contents(__DIR__ . $this->passwordPath)
        );
        $data = 'hello';
        $encrypted = $rsa->base64Encrypt($data);
        $decrypted = $rsa->base64Decrypt($encrypted);
        $this->assertEquals($decrypted, $data);
    }
}