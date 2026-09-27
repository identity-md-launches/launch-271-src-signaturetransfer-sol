// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Signature-authorized ERC-20 transfers using Permit2's EIP-712 messages.
/// @dev The signed spender is msg.sender. That spender chooses the recipient and any
/// amount up to the signed limit. Nonces are shared by all four permit entry points.
/// Two deliberate hardenings over canonical Permit2: EOA signatures with s above
/// secp256k1n/2 revert InvalidSigner(), and token addresses without code revert
/// TransferFromFailed(), including when the requested amount is zero.
contract SignatureTransfer {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct PermitBatchTransferFrom {
        TokenPermissions[] permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    error SignatureExpired(uint256 signatureDeadline);
    error InvalidAmount(uint256 maxAmount);
    error LengthMismatch();
    error InvalidNonce();
    error InvalidSignatureLength();
    error InvalidSigner();
    error InvalidContractSignature();
    error TransferFromFailed();

    event UnorderedNonceInvalidation(address indexed owner, uint256 word, uint256 mask);

    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("Permit2");
    bytes32 private constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 private constant PERMIT_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );
    bytes32 private constant BATCH_TYPEHASH = keccak256(
        "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );
    string private constant WITNESS_STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    string private constant BATCH_WITNESS_STUB =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,";
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;

    uint256 private immutable cachedChainId;
    bytes32 private immutable cachedDomainSeparator;

    constructor() {
        cachedChainId = block.chainid;
        cachedDomainSeparator = _buildDomainSeparator();
    }

    /// @notice The Permit2 domain, without a version field; follows chain ID changes.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == cachedChainId ? cachedDomainSeparator : _buildDomainSeparator();
    }

    function permitTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, _hashPermissions(permit.permitted), msg.sender, permit.nonce, permit.deadline)
        );
        _execute(permit, transferDetails, owner, structHash, signature);
    }

    function permitTransferFrom(
        PermitBatchTransferFrom calldata permit,
        SignatureTransferDetails[] calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(
                BATCH_TYPEHASH, _hashPermissionsArray(permit.permitted), msg.sender, permit.nonce, permit.deadline
            )
        );
        _executeBatch(permit, transferDetails, owner, structHash, signature);
    }

    /// @dev witnessTypeString completes the primary type and includes all dependent
    /// type definitions in EIP-712 order, including TokenPermissions. Its exact bytes
    /// are signed; no parsing or normalization is performed.
    function permitWitnessTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external {
        bytes32 typeHash = keccak256(abi.encodePacked(WITNESS_STUB, witnessTypeString));
        bytes32 structHash = keccak256(
            abi.encode(typeHash, _hashPermissions(permit.permitted), msg.sender, permit.nonce, permit.deadline, witness)
        );
        _execute(permit, transferDetails, owner, structHash, signature);
    }

    /// @dev Uses the same witness type suffix convention as the single-token overload.
    function permitWitnessTransferFrom(
        PermitBatchTransferFrom calldata permit,
        SignatureTransferDetails[] calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external {
        bytes32 typeHash = keccak256(abi.encodePacked(BATCH_WITNESS_STUB, witnessTypeString));
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash, _hashPermissionsArray(permit.permitted), msg.sender, permit.nonce, permit.deadline, witness
            )
        );
        _executeBatch(permit, transferDetails, owner, structHash, signature);
    }

    /// @notice Permanently marks the selected bits in the caller's nonce word as used.
    function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
        nonceBitmap[msg.sender][wordPos] |= mask;
        emit UnorderedNonceInvalidation(msg.sender, wordPos, mask);
    }

    function _execute(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata details,
        address owner,
        bytes32 structHash,
        bytes calldata signature
    ) private {
        if (block.timestamp > permit.deadline) revert SignatureExpired(permit.deadline);
        if (details.requestedAmount > permit.permitted.amount) revert InvalidAmount(permit.permitted.amount);
        _useNonce(owner, permit.nonce);
        _verify(owner, structHash, signature);
        _transfer(permit.permitted.token, owner, details.to, details.requestedAmount);
    }

    function _executeBatch(
        PermitBatchTransferFrom calldata permit,
        SignatureTransferDetails[] calldata details,
        address owner,
        bytes32 structHash,
        bytes calldata signature
    ) private {
        if (block.timestamp > permit.deadline) revert SignatureExpired(permit.deadline);
        if (permit.permitted.length != details.length) revert LengthMismatch();
        _useNonce(owner, permit.nonce);
        _verify(owner, structHash, signature);
        for (uint256 i; i < details.length; ++i) {
            if (details[i].requestedAmount > permit.permitted[i].amount) {
                revert InvalidAmount(permit.permitted[i].amount);
            }
            _transfer(permit.permitted[i].token, owner, details[i].to, details[i].requestedAmount);
        }
    }

    function _useNonce(address owner, uint256 nonce) private {
        uint256 word = nonce >> 8;
        uint256 bit = uint256(1) << (nonce & 0xff);
        uint256 bitmap = nonceBitmap[owner][word];
        if (bitmap & bit != 0) revert InvalidNonce();
        // Consume before any external call; a failed signature or transfer rolls this back.
        nonceBitmap[owner][word] = bitmap | bit;
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, block.chainid, address(this)));
    }

    function _hashPermissions(TokenPermissions calldata permitted) private pure returns (bytes32) {
        return keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permitted.token, permitted.amount));
    }

    function _hashPermissionsArray(TokenPermissions[] calldata permitted) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](permitted.length);
        for (uint256 i; i < permitted.length; ++i) {
            hashes[i] = _hashPermissions(permitted[i]);
        }
        // EIP-712 arrays contain only the concatenated element hashes, without a length.
        return keccak256(abi.encodePacked(hashes));
    }

    function _verify(address owner, bytes32 structHash, bytes calldata signature) private view {
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), structHash));
        if (owner.code.length != 0) {
            (bool success, bytes memory result) =
                owner.staticcall(abi.encodeWithSelector(ERC1271_MAGIC, digest, signature));
            if (!success || result.length < 32 || bytes4(result) != ERC1271_MAGIC) {
                revert InvalidContractSignature();
            }
            return;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signature.length == 65) {
            (r, s) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(signature[64]);
        } else if (signature.length == 64) {
            bytes32 vs;
            (r, vs) = abi.decode(signature, (bytes32, bytes32));
            s = bytes32(uint256(vs) & (type(uint256).max >> 1));
            v = uint8(uint256(vs) >> 255) + 27;
        } else {
            revert InvalidSignatureLength();
        }
        if (uint256(s) > SECP256K1_HALF_ORDER) revert InvalidSigner();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != owner) revert InvalidSigner();
    }

    function _transfer(address token, address owner, address to, uint256 amount) private {
        if (token.code.length == 0) revert TransferFromFailed();
        // A zero request consumes the nonce without calling the token.
        if (amount == 0) return;
        (bool success, bytes memory result) = token.call(abi.encodeWithSelector(bytes4(0x23b872dd), owner, to, amount));
        if (!success || (result.length != 0 && (result.length < 32 || abi.decode(result, (uint256)) != 1))) {
            revert TransferFromFailed();
        }
    }
}
