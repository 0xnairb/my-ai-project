// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/EIP712Verify.sol";
import "forge-std/console.sol";

contract EIP712VerifyTest is Test {
    EIP712Verify public verifier;
    uint256 internal signerPrivateKey;
    address internal signer;

    function setUp() public {
        verifier = new EIP712Verify();
        signerPrivateKey = 0xA11CE;  // Use a known private key for testing
        signer = vm.addr(signerPrivateKey);
    }

    function testVerification() public {
        // Create a mail struct
        EIP712Verify.Mail memory mail = EIP712Verify.Mail({
            name: "Alice",
            email: "alice@example.com"
        });

        // Get the hash of the mail
        bytes32 digest = verifier.hashMail(mail);

        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify the signature
        bool isValid = verifier.verify(mail, signer, signature);
        assertTrue(isValid, "Signature verification failed");
    }

    function testInvalidSignature() public {
        // Create a mail struct
        EIP712Verify.Mail memory mail = EIP712Verify.Mail({
            name: "Alice",
            email: "alice@example.com"
        });

        // Get the hash of the mail
        bytes32 digest = verifier.hashMail(mail);

        // Sign with a different private key
        uint256 wrongPrivateKey = 0xB0B;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify should fail
        bool isValid = verifier.verify(mail, signer, signature);
        assertFalse(isValid, "Signature verification should have failed");
    }
}