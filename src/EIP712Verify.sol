// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract EIP712Verify is EIP712 {
    using ECDSA for bytes32;

    struct Mail {
        string name;
        string email;
    }

    bytes32 constant MAIL_TYPEHASH = keccak256("Mail(string name,string email)");

    constructor() EIP712("EIP712Verify", "1.0.0") {}

    function hashMail(Mail memory mail) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            MAIL_TYPEHASH,
            keccak256(bytes(mail.name)),
            keccak256(bytes(mail.email))
        )));
    }

    function verify(Mail memory mail, address signer, bytes memory signature) public view returns (bool) {
        bytes32 digest = hashMail(mail);
        return ECDSA.recover(digest, signature) == signer;
    }
}