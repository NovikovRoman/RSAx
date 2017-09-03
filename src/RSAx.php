<?php

namespace RSAx;

/**
 * Class RSAx
 * @package RSAx
 *
 * thanks:
 *      https://github.com/vlucas/pikirasa
 *      http://php.net
 *      https://stackexchange.com
 */
class RSAx
{
    const PREFIX_FILE = 'file://';

    private $publicKeyFile;
    private $privateKeyFile;
    private $password;

    public function __construct($publicKeyFile = null, $privateKeyFile = null, $password = null)
    {
        $this->publicKeyFile = $this->fixKeyArgument($publicKeyFile);
        $this->privateKeyFile = $this->fixKeyArgument($privateKeyFile);
        $this->password = $password;
    }

    public function fixKeyArgument($keyFile)
    {
        if (strpos($keyFile, '/') === 0) {
            return self::PREFIX_FILE . $keyFile;
        }
        return $keyFile;
    }

    public function generate($config, $password = false)
    {
        if ($password) {
            $config['encrypt_key'] = true;
        }
        $this->password = $password;
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey, $password);
        $pubKey = openssl_pkey_get_details($res);
        $this->publicKeyFile = $pubKey['key'];
        $this->privateKeyFile = $privateKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        $pattern = preg_quote(self::PREFIX_FILE, '/');
        if (preg_match('/^' . $pattern . '/sui', $this->publicKeyFile)) {
            return file_get_contents($this->publicKeyFile);
        }
        return $this->publicKeyFile;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        $pattern = preg_quote(self::PREFIX_FILE, '/');
        if (preg_match('/^' . $pattern . '/sui', $this->privateKeyFile)) {
            return file_get_contents($this->privateKeyFile);
        }
        return $this->privateKeyFile;
    }

    /**
     * Set password to be used during encryption and decryption
     *
     * @param string $password Certificate password
     */
    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Encrypt data with provided public certificate
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data
     *
     * @throws Exception
     */
    public function encrypt($data)
    {
        // Load public key
        $publicKey = openssl_pkey_get_public($this->publicKeyFile);
        if (!$publicKey) {
            throw new Exception('OpenSSL: Unable to get public key for encryption. Is the location correct? Does this key require a password?');
        }
        $detailsPublicKey = openssl_pkey_get_details($publicKey);
        $bytes = $detailsPublicKey['bits'] / 8 - 11;
        $encodedData = '';
        foreach (str_split($data, $bytes) as $part) {
            $success = openssl_public_encrypt($part, $partialData, $publicKey, OPENSSL_PKCS1_PADDING);
            if (!$success) {
                throw new Exception('Encryption failed. Ensure you are using a PUBLIC key.');
            }
            $encodedData .= $partialData;
        }
        openssl_free_key($publicKey);
        return $encodedData;
    }

    /**
     * Decrypt data with provided private certificate
     *
     * @param string $data Data to encrypt
     * @return string Decrypted data
     *
     * @throws Exception
     */
    public function decrypt($data)
    {
        if ($this->privateKeyFile === null) {
            throw new Exception('Unable to decrypt: No private key provided.');
        }
        $privateKey = openssl_pkey_get_private($this->privateKeyFile, $this->password);
        if (!$privateKey) {
            throw new Exception('OpenSSL: Unable to get private key for decryption');
        }
        $detailsPrivateKey = openssl_pkey_get_details($privateKey);
        $bytes = $detailsPrivateKey['bits'] / 8;
        $originalData = '';
        foreach (str_split($data, $bytes) as $part) {
            $success = openssl_private_decrypt($part, $partialData, $privateKey);
            if (!$success) {
                throw new Exception('Decryption failed. Ensure you are using (1) A PRIVATE key, and (2) the correct one.');
            }
            $originalData .= $partialData;
        }
        openssl_free_key($privateKey);
        return $originalData;
    }

    /**
     * Encrypt data and then base64_encode it
     *
     * @param string $data Data to encrypt
     * @return string Base64-encrypted data
     */
    public function base64Encrypt($data)
    {
        return base64_encode($this->encrypt($data));
    }

    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @return string Decrypted data
     */
    public function base64Decrypt($data)
    {
        return $this->decrypt(base64_decode($data));
    }
}