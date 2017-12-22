<?php

namespace Otp\Tests;

use Otp\Otp;
use PHPUnit\Framework\TestCase;

/**
 * Otp test case.
 */
class OtpTest extends TestCase {
    /**
     *
     * @var Otp
     */
    private $Otp;

    private $secret = "12345678901234567890";

    /**
     * Prepares the environment before running a test.
     */
    protected function setUp() {
        parent::setUp();

        $this->Otp = new Otp();
    }

    /**
     * Cleans up the environment after running a test.
     */
    protected function tearDown() {
        $this->Otp = null;

        parent::tearDown();
    }

    /**
     * Invalid counter values for tests.
     */
    public function hotpTestValues() {
        return [
                 ['755224', 0], ['287082', 1], ['359152', 2],
                 ['969429', 3], ['338314', 4], ['254676', 5],
                 ['287922', 6], ['162583', 7], ['399871', 8],
                 ['520489', 9]
               ];
    }

    /**
     * Invalid counter values for tests.
     */
    public function totpTestValues() {
        return [
                 ['94287082', 59], ['07081804', 1111111109], ['14050471', 1111111111],
                 ['89005924', 1234567890], ['69279037', 2000000000], ['65353130', 20000000000],
               ];
    }

    /**
     * Invalid counter values for tests.
     */
    public function invalidCounterValues() {
        return [
                 ['a'], [-1]
               ];
    }

    /**
     * Invalid counter values for tests.
     */
    public function hotpResyncDefaultTestValues() {
        return [
                 ['755224', 0], ['287082', 1], ['359152', 2]
               ];
    }

    /**
     * Invalid counter values for tests.
     */
    public function hotpResyncWindowTestValues() {
        return [
                 ['969429', 0, 3], ['338314', 0, 4],
                 ['287922', 3, 3], ['162583', 3, 4]
               ];
    }

    /**
     * Invalid counter values for tests.
     */
    public function hotpResyncFailureTestValues() {
        return [
                 ['287922', 7], ['162583', 8], ['399871', 9]
               ];
    }

    /**
     * Tests Otp->hotp().
     *
     * Using test vectors from RFC
     * https://tools.ietf.org/html/rfc4226
     *
     * @dataProvider hotpTestValues
     */
    public function testHotpRfc($key, $counter) {
        $secret = $this->secret;

        $this->assertEquals($key, $this->Otp->hotp($secret, $counter));
    }

    /**
     * Tests TOTP general construction.
     *
     * Still uses the hotp function, but since totp is a bit more special, has
     * its own tests
     * Using test vectors from RFC
     * https://tools.ietf.org/html/rfc6238
     *
     * @dataProvider totpTestValues
     */
    public function testTotpRfc($key, $time) {
        $secret = $this->secret;

        // Test vectors are in 8 digits
        $this->Otp->setDigits(8);

        // The time presented in the test vector has to be first divided through 30
        // to count as the key

        // SHA 1 grouping
        $this->assertEquals($key, $this->Otp->hotp($secret, \floor($time/30)), "sha 1 with $time");


        /*
        The following tests do NOT pass.
        Once the otp class can deal with these correctly, they can be used again.
        They are here for completeness test vectors from the RFC.

        // SHA 256 grouping
        $this->Otp->setAlgorithm('sha256');
        $this->assertEquals('46119246', $this->Otp->hotp($secret,          floor(59/30)), 'sha256 with time 59');
        $this->assertEquals('07081804', $this->Otp->hotp($secret,  floor(1111111109/30)), 'sha256 with time 1111111109');
        $this->assertEquals('14050471', $this->Otp->hotp($secret,  floor(1111111111/30)), 'sha256 with time 1111111111');
        $this->assertEquals('89005924', $this->Otp->hotp($secret,  floor(1234567890/30)), 'sha256 with time 1234567890');
        $this->assertEquals('69279037', $this->Otp->hotp($secret,  floor(2000000000/30)), 'sha256 with time 2000000000');
        $this->assertEquals('65353130', $this->Otp->hotp($secret, floor(20000000000/30)), 'sha256 with time 20000000000');

        // SHA 512 grouping
        $this->Otp->setAlgorithm('sha512');
        $this->assertEquals('90693936', $this->Otp->hotp($secret,          floor(59/30)), 'sha512 with time 59');
        $this->assertEquals('25091201', $this->Otp->hotp($secret,  floor(1111111109/30)), 'sha512 with time 1111111109');
        $this->assertEquals('99943326', $this->Otp->hotp($secret,  floor(1111111111/30)), 'sha512 with time 1111111111');
        $this->assertEquals('93441116', $this->Otp->hotp($secret,  floor(1234567890/30)), 'sha512 with time 1234567890');
        $this->assertEquals('38618901', $this->Otp->hotp($secret,  floor(2000000000/30)), 'sha512 with time 2000000000');
        $this->assertEquals('47863826', $this->Otp->hotp($secret, floor(20000000000/30)), 'sha512 with time 20000000000');
        */
    }

    /**
     * Tests $this->Otp->totp.
     */
    public function testTotp() {
        $secret = $this->secret;

        $this->assertEquals('755224', $this->Otp->totp($secret, \floor(8/30)), "sha 1 with 8");
        $this->assertInternalType('string', $this->Otp->totp($secret), "sha 1 with random time counter");
    }

    /**
     * Tests $this->Otp->checkHotp.
     */
    public function testCheckHotp() {
        $secret = $this->secret;

        $this->assertTrue($this->Otp->checkHotp($secret, \floor(8/30), '755224'), "sha 1 with 8");
    }

    /**
     * Tests $this->Otp->checkTotp with non-worked.
     */
    public function testCheckTotpWithNoneWorked() {
        $secret = $this->secret;

        $this->assertFalse($this->Otp->checkTotp($secret, '755224'));
    }

    /**
     * Tests $this->Otp->checkTotp with time drift is zero.
     */
    public function testCheckTotpWithTimeDriftZero() {
        $secret = $this->secret;

        $this->assertFalse($this->Otp->checkTotp($secret, '755224', 0));
    }

    /**
     * Tests $this->Otp->checkTotp with time drift is invalid.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid timedrift supplied
     */
    public function testCheckTotpWithInvalidTimeDrift() {
        $secret = $this->secret;
        $this->Otp->checkTotp($secret, '755224', -1);
    }

    /**
     * @dataProvider invalidCounterValues
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid counter supplied
     */
    public function testHotpInvalidCounter($counter) {
        $this->Otp->hotp($this->secret, $counter);
    }

    /**
     * Tests Otp->checkHotpResync() with default counter window.
     *
     * @dataProvider hotpResyncDefaultTestValues
     */
    public function testHotpResyncDefault($key, $counter) {
        $secret = $this->secret;

        // test with default counter window
        $this->assertSame($counter, $this->Otp->checkHotpResync($secret, $counter, $key));
    }


    /**
     * Tests Otp->checkHotpResync() with a provided counter window.
     *
     * @dataProvider hotpResyncWindowTestValues
     */
    public function testHotpResyncWindow($key, $counter, $counterwindow) {
        $secret = $this->secret;

        // test with provided counter window
        $this->assertSame(($counter + $counterwindow), $this->Otp->checkHotpResync($secret, $counter, $key, $counterwindow));
    }

    /**
     * Tests Otp->checkHotpResync() with mismatching key and counter.
     *
     * @dataProvider hotpResyncFailureTestValues
     */
    public function testHotpResyncFailures($key, $counter) {
        $secret = $this->secret;

        // test failures
        $this->assertFalse($this->Otp->checkHotpResync($secret, $counter, $key));
    }

    /**
     * @dataProvider invalidCounterValues
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid counter supplied
     */
    public function testHotpResyncInvalidCounter($counter) {
        $this->Otp->checkHotpResync($this->secret, $counter, '755224');
    }

    /**
     * @dataProvider invalidCounterValues
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid counterwindow supplied
     */
    public function testHotpResyncInvalidCounterWindow($counterwindow) {
        $this->Otp->checkHotpResync($this->secret, 0, '755224', $counterwindow);
    }

    /**
     * Tests Otp->getAlgorithm() with getting the algorithm name.
     */
    public function testGetAlgorithm() {
        $this->assertEquals('sha1', $this->Otp->getAlgorithm());
    }

    /**
     * Tests Otp->setPeriod() with setting period.
     */
    public function testSetPeriod() {
        $this->assertInstanceOf('Otp\Otp', $this->Otp->setPeriod(100));
    }

    /**
     * Tests Otp->getPeriod() with getting period.
     */
    public function testGetPeriod() {
        $this->assertEquals(30, $this->Otp->getPeriod());
    }

    /**
     * Tests Otp->setPeriod() with setting invalid period.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Period must be an integer
     */
    public function testSetPeriodWithInvalid() {
        $this->Otp->setPeriod(0.1);
    }

    /**
     * Tests Otp->setDigits() with setting invalid digits.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Digits must be 6 or 8
     */
    public function testSetDigitsWithInvalid() {
        $this->Otp->setDigits(10);
    }

    /**
     * Tests Otp->getDigits() with getting digits.
     */
    public function testGetDigits() {
        $this->assertEquals(6, $this->Otp->getDigits());
    }

    /**
     * Tests Otp->setTotpOffset() with setting totp offset.
     */
    public function testSetTotpOffset() {
        $this->assertInstanceOf('Otp\Otp', $this->Otp->setTotpOffset(100));
    }

    /**
     * Tests Otp->getTotpOffset() with getting totp offset.
     */
    public function testGetTotpOffset() {
        $this->Otp->setTotpOffset(100);

        $this->assertEquals(100, $this->Otp->getTotpOffset());
    }

    /**
     * Tests Otp->setTotpOffset() with setting invalid totp offset.
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Offset must be an integer
     */
    public function testSetTotpOffsetWithInvalid() {
        $this->Otp->setTotpOffset(0.1);
    }
}
