<?php

namespace Otp\Tests;

use Otp\GoogleAuthenticator;
use PHPUnit\Framework\TestCase;

/**
 * GoogleAuthenticator test case.
 */
class GoogleAuthenticatorTest extends TestCase {
    /**
     * Tests getQrCodeUrl.
     */
    public function testGetQrCodeUrl() {
        $secret = 'MEP3EYVA6XNFNVNM'; // testing secret

        // Standard totp case
        $this->assertEquals(
            'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chld=M|0&chl=otpauth%3A%2F%2Ftotp%2Fuser%40host.com%3Fsecret%3DMEP3EYVA6XNFNVNM',
            GoogleAuthenticator::getQrCodeUrl('totp', 'user@host.com', $secret)
        );

        // hotp (include a counter)
        $this->assertEquals(
            'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chld=M|0&chl=otpauth%3A%2F%2Fhotp%2Fuser%40host.com%3Fsecret%3DMEP3EYVA6XNFNVNM%26counter%3D1234',
            GoogleAuthenticator::getQrCodeUrl('hotp', 'user@host.com', $secret, 1234)
        );

        // totp, this time with a parameter for chaning the size of the QR
        $this->assertEquals(
                'https://chart.googleapis.com/chart?chs=300x300&cht=qr&chld=M|0&chl=otpauth%3A%2F%2Ftotp%2Fuser%40host.com%3Fsecret%3DMEP3EYVA6XNFNVNM',
                GoogleAuthenticator::getQrCodeUrl('totp', 'user@host.com', $secret, null, ['height' => 300, 'width' => 300])
        );
    }

    /**
     * Tests getKeyUri.
     */
    public function testGetKeyUri() {
        $secret = 'MEP3EYVA6XNFNVNM'; // testing secret

        // Standard totp case
        $this->assertEquals(
            'otpauth://totp/user@host.com?secret=MEP3EYVA6XNFNVNM',
            GoogleAuthenticator::getKeyUri('totp', 'user@host.com', $secret)
        );

        // hotp (include a counter)
        $this->assertEquals(
            'otpauth://hotp/user@host.com?secret=MEP3EYVA6XNFNVNM&counter=1234',
            GoogleAuthenticator::getKeyUri('hotp', 'user@host.com', $secret, 1234)
        );

        // totp/hotp with an issuer in the label
        $this->assertEquals(
            'otpauth://hotp/issuer%3Auser@host.com?secret=MEP3EYVA6XNFNVNM&counter=1234',
            GoogleAuthenticator::getKeyUri('hotp', 'issuer:user@host.com', $secret, 1234)
        );

        // totp/hotp with an issuer and spaces in the label
        $this->assertEquals(
            'otpauth://hotp/an%20issuer%3A%20user@host.com?secret=MEP3EYVA6XNFNVNM&counter=1234',
            GoogleAuthenticator::getKeyUri('hotp', 'an issuer: user@host.com', $secret, 1234)
        );

        // totp/hotp with an issuer as option
        $this->assertEquals(
            'otpauth://hotp/an%20issuer%3Auser@host.com?secret=MEP3EYVA6XNFNVNM&counter=1234&issuer=an%20issuer',
            GoogleAuthenticator::getKeyUri('hotp', 'an issuer:user@host.com', $secret, 1234, ['issuer' => 'an issuer'])
        );
    }

    /**
     * Tests getKeyUri invalid type.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Type has to be of allowed types list
     */
    public function testGetKeyUriWithInvalidType() {
        // throw the invalid type exception message
        GoogleAuthenticator::getKeyUri('error_type', 'user@host.com', 'secret');
    }

    /**
     * Tests getKeyUri empty label.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Label has to be one or more printable characters
     */
    public function testGetKeyUriWithEmptyLabel() {
        // throw the empty label exception message
        GoogleAuthenticator::getKeyUri('hotp', '', 'secret');
    }

    /**
     * Tests getKeyUri label contains invalid characters.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Account name contains illegal colon characters
     */
    public function testGetKeyUriWithLabelContainsInvalidCharatcer() {
        // throw the label contains invalid characters exception message
        GoogleAuthenticator::getKeyUri('hotp', 'illegal:char1:char2:char3:char4', 'secret');
    }

    /**
     * Tests getKeyUri empty secret.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No secret present
     */
    public function testGetKeyUriWithEmptySecret() {
        // throw the empty secret exception message
        GoogleAuthenticator::getKeyUri('hotp', 'user@host.com', '');
    }

    /**
     * Tests getKeyUri hotp doesn't have the counter.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Counter required for hotp
     */
    public function testGetKeyUriWithHotpHasNullCounter() {
        // throw the hotp having null counter exception message
        GoogleAuthenticator::getKeyUri('hotp', 'user@host.com', 'secret');
    }

    /**
     * Tests getKeyUri options specifies other algorithm.
     */
    public function testGetKeyUriWithOptionHasOtherAlgorithm() {
        // the options have the algorithm key.
        $this->assertEquals(
            'otpauth://hotp/user@host.com?secret=secret&counter=123&algorithm=SHA2',
            GoogleAuthenticator::getKeyUri('hotp', 'user@host.com', 'secret', 123, ['algorithm' => 'SHA2'])
        );
    }

    /**
     * Tests getKeyUri customized digits is valid.
     */
    public function testGetKeyUriWithOptionHasValidDigits() {
        // the customized digits is valid.
        $this->assertEquals(
            'otpauth://hotp/user@host.com?secret=secret&counter=123&digits=8',
            GoogleAuthenticator::getKeyUri('hotp', 'user@host.com', 'secret', 123, ['digits' => 8])
        );
    }

    /**
     * Tests getKeyUri customized digits is invalid.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Digits can only have the values 6 or 8, 100 given
     */
    public function testGetKeyUriWithOptionHasInvalidDigits() {
        // the customized digits is invalid.
        GoogleAuthenticator::getKeyUri('hotp', 'user@host.com', 'secret', 123, ['digits' => 100]);
    }

    /**
     * Tests getKeyUri totp type has the customized period.
     */
    public function testGetKeyUriWithOptionHasPeriod() {
        // the customized period is set in totp type.
        $this->assertEquals(
            'otpauth://totp/user@host.com?secret=secret&period=20',
            GoogleAuthenticator::getKeyUri('totp', 'user@host.com', 'secret', null, ['period' => 20])
        );
    }

    /**
     * Tests getKeyUri the freeotp type option is set the image.
     */
    public function testGetKeyUriWithOptionHasImage() {
        // accept the image option in freeotp type.
        $this->assertEquals(
            'otpauth://totp/user@host.com?secret=secret&image=the_image',
            GoogleAuthenticator::getKeyUri('totp', 'user@host.com', 'secret', null, ['image' => 'the_image'])
        );
    }

    /**
     * Tests generateRandom.
     */
    public function testGenerateRandom() {
        // contains numbers 2-7 and letters A-Z in large letters, 16 chars long
        $this->assertRegExp('/[2-7A-Z]{16}/', GoogleAuthenticator::generateRandom());

        // Can be told to make a longer secret
        $this->assertRegExp('/[2-7A-Z]{18}/', GoogleAuthenticator::generateRandom(18));
    }

    /**
     * Test generateRecoveryCodes.
     */
    public function testGenerateRecoveryCodes() {
        // Default settings
        $codes = GoogleAuthenticator::generateRecoveryCodes();

        $this->assertCount(1, $codes);
        $this->assertRegExp('/[0-9]{9}/', $codes[0]);

        // More codes, longer
        $codes = GoogleAuthenticator::generateRecoveryCodes(4, 20);
        $this->assertCount(4, $codes);
        $this->assertRegExp('/[0-9]{9}/', $codes[0]);
        $this->assertRegExp('/[0-9]{9}/', $codes[1]);
        $this->assertRegExp('/[0-9]{9}/', $codes[2]);
        $this->assertRegExp('/[0-9]{9}/', $codes[3]);

        // To check for uniqueness
        $this->assertSame($codes, \array_unique($codes));
    }
}
