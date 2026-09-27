// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureTransfer} from "../src/SignatureTransfer.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function chainId(uint256 newChainId) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata revertData) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
}

contract SignatureTransferToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public calls;
    uint8 public returnMode;
    SignatureTransfer private watchedTransfer;
    address private watchedOwner;
    uint256 private watchedNonce;
    bytes private reentry;
    bool public reentryAttempted;
    bytes4 public reentryError;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setBalance(address to, uint256 amount) external {
        balanceOf[to] = amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // 0 = true, 1 = no return data, 2 = false, 3 = revert, 4 = short data, 5 = non-boolean word.
    function setReturnMode(uint8 mode) external {
        returnMode = mode;
    }

    function watchNonce(SignatureTransfer target, address owner, uint256 nonce) external {
        watchedTransfer = target;
        watchedOwner = owner;
        watchedNonce = nonce;
    }

    function setReentry(bytes calldata payload) external {
        reentry = payload;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (address(watchedTransfer) != address(0)) {
            require(
                watchedTransfer.nonceBitmap(watchedOwner, watchedNonce / 256) & (uint256(1) << (watchedNonce % 256))
                    != 0,
                "token called before nonce consumption"
            );
        }
        if (reentry.length != 0 && !reentryAttempted) {
            reentryAttempted = true;
            (bool success, bytes memory result) = address(watchedTransfer).call(reentry);
            require(!success && result.length >= 4, "replay succeeded during transfer");
            reentryError = bytes4(result);
        }
        ++calls;
        uint256 approved = allowance[from][msg.sender];
        require(approved >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        if (approved != type(uint256).max) allowance[from][msg.sender] = approved - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        if (returnMode == 1) {
            assembly { return(0, 0) }
        }
        if (returnMode == 2) return false;
        if (returnMode == 3) revert("token rejected transfer");
        if (returnMode == 4) {
            assembly {
                mstore(0, 1)
                return(31, 1)
            }
        }
        if (returnMode == 5) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        return true;
    }
}

contract SignatureTransferWallet {
    SignatureTransfer private immutable target;
    SignatureTransferToken private immutable token;
    SignatureTransferToken private immutable secondToken;
    bytes32 private expectedDigest;
    bytes32 private expectedSignatureHash;
    uint256 private expectedNonce;
    uint256 private expectedBalance;
    uint256 private expectedSecondBalance;
    uint256 private expectedCalls;
    uint256 private expectedSecondCalls;
    uint8 private mode;

    constructor(SignatureTransfer transfer, SignatureTransferToken first, SignatureTransferToken second) {
        target = transfer;
        token = first;
        secondToken = second;
        first.approve(address(transfer), type(uint256).max);
        second.approve(address(transfer), type(uint256).max);
    }

    function configure(bytes32 digest, bytes calldata signature, uint256 nonce, uint8 responseMode) external {
        expectedDigest = digest;
        expectedSignatureHash = keccak256(signature);
        expectedNonce = nonce;
        expectedBalance = token.balanceOf(address(this));
        expectedSecondBalance = secondToken.balanceOf(address(this));
        expectedCalls = token.calls();
        expectedSecondCalls = secondToken.calls();
        mode = responseMode;
    }

    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        require(msg.sender == address(target), "unexpected validator caller");
        require(digest == expectedDigest && keccak256(signature) == expectedSignatureHash, "unsigned message");
        require(
            target.nonceBitmap(address(this), expectedNonce / 256) & (uint256(1) << (expectedNonce % 256)) != 0,
            "wallet called before nonce consumption"
        );
        require(
            token.balanceOf(address(this)) == expectedBalance
                && secondToken.balanceOf(address(this)) == expectedSecondBalance && token.calls() == expectedCalls
                && secondToken.calls() == expectedSecondCalls,
            "tokens moved before signature check"
        );
        if (mode == 1) return 0xffffffff;
        if (mode == 2) revert("wallet rejected signature");
        if (mode == 3) {
            assembly { return(0, 0) }
        }
        if (mode == 4) {
            assembly {
                mstore(0, shl(224, 0x1626ba7e))
                return(0, 4)
            }
        }
        return 0x1626ba7e;
    }
}

/// @dev Every digest below is built from the public specification, without calling
/// the implementation's DOMAIN_SEPARATOR or accessing its private hash helpers.
contract SignatureTransferTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant OWNER_KEY = 0xa11ce;
    uint256 private constant OTHER_KEY = 0xb0b;
    uint256 private constant INITIAL_BALANCE = 1e30;
    uint256 private constant NOW = 1_700_000_000;
    uint256 private constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    address private constant SPENDER_A = address(0xa000);
    address private constant SPENDER_B = address(0xb000);
    address private constant RECIPIENT = address(0xc000);
    address private constant SECOND_RECIPIENT = address(0xd000);

    string private constant WITNESS_SUFFIX =
        "Mock witness)Mock(uint256 a)TokenPermissions(address token,uint256 amount)";
    string private constant OTHER_WITNESS_SUFFIX =
        "Mock witness)Mock(uint256 b)TokenPermissions(address token,uint256 amount)";
    string private constant INJECTED_SUFFIX =
        "Mock witness)Mock(uint256 a)TokenPermissions(address token,uint256 amount)X(";
    bytes32 private constant TOKEN_TYPE = keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 private constant SINGLE_TYPE = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );
    bytes32 private constant BATCH_TYPE = keccak256(
        "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );
    // Complete canonical types deliberately avoid the implementation's stub concatenation.
    bytes32 private constant SINGLE_WITNESS_TYPE = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Mock witness)Mock(uint256 a)TokenPermissions(address token,uint256 amount)"
    );
    bytes32 private constant BATCH_WITNESS_TYPE = keccak256(
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mock witness)Mock(uint256 a)TokenPermissions(address token,uint256 amount)"
    );

    // Routes: 0 single, 1 batch, 2 witness, 3 batch witness.
    struct Case {
        uint8 route;
        SignatureTransfer.PermitBatchTransferFrom permit;
        SignatureTransfer.SignatureTransferDetails[] details;
        address owner;
        address spender;
        bytes32 witness;
        string witnessTypeString;
    }

    SignatureTransfer private target;
    SignatureTransferToken private token;
    SignatureTransferToken private secondToken;
    address private owner;

    event UnorderedNonceInvalidation(address indexed owner, uint256 word, uint256 mask);

    function setUp() public {
        vm.warp(NOW);
        target = new SignatureTransfer();
        token = new SignatureTransferToken();
        secondToken = new SignatureTransferToken();
        owner = vm.addr(OWNER_KEY);
        _fund(owner);
        vm.prank(owner);
        token.approve(address(target), type(uint256).max);
        vm.prank(owner);
        secondToken.approve(address(target), type(uint256).max);
    }

    function _fund(address account) private {
        token.mint(account, INITIAL_BALANCE);
        secondToken.mint(account, INITIAL_BALANCE);
    }

    function _case(uint8 route) private view returns (Case memory c) {
        c.route = route;
        c.owner = owner;
        c.spender = SPENDER_A;
        c.witness = keccak256(abi.encode(keccak256("Mock(uint256 a)"), uint256(42)));
        c.witnessTypeString = WITNESS_SUFFIX;
        uint256 length = route % 2 == 0 ? 1 : 2;
        c.permit = SignatureTransfer.PermitBatchTransferFrom({
            permitted: new SignatureTransfer.TokenPermissions[](length), nonce: route, deadline: NOW + 1 days
        });
        c.details = new SignatureTransfer.SignatureTransferDetails[](length);
        c.permit.permitted[0] = SignatureTransfer.TokenPermissions(address(token), 100);
        c.details[0] = SignatureTransfer.SignatureTransferDetails(RECIPIENT, 60);
        if (length == 2) {
            c.permit.permitted[1] = SignatureTransfer.TokenPermissions(address(secondToken), 200);
            c.details[1] = SignatureTransfer.SignatureTransferDetails(SECOND_RECIPIENT, 90);
        }
    }

    function _single(Case memory c) private pure returns (SignatureTransfer.PermitTransferFrom memory) {
        return SignatureTransfer.PermitTransferFrom(c.permit.permitted[0], c.permit.nonce, c.permit.deadline);
    }

    function _domain(address verifyingContract, uint256 chain) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("Permit2"),
                chain,
                verifyingContract
            )
        );
    }

    function _permissionsHash(Case memory c) private pure returns (bytes32) {
        if (c.route % 2 == 0) {
            return keccak256(abi.encode(TOKEN_TYPE, c.permit.permitted[0].token, c.permit.permitted[0].amount));
        }
        bytes memory concatenated;
        for (uint256 i; i < c.permit.permitted.length; ++i) {
            bytes32 element =
                keccak256(abi.encode(TOKEN_TYPE, c.permit.permitted[i].token, c.permit.permitted[i].amount));
            concatenated = bytes.concat(concatenated, element);
        }
        return keccak256(concatenated);
    }

    function _typeHash(uint8 route) private pure returns (bytes32) {
        if (route == 0) return SINGLE_TYPE;
        if (route == 1) return BATCH_TYPE;
        if (route == 2) return SINGLE_WITNESS_TYPE;
        return BATCH_WITNESS_TYPE;
    }

    function _structHash(Case memory c, bytes32 typeHash, bytes32 permissionsHash) private pure returns (bytes32) {
        if (c.route < 2) {
            return keccak256(abi.encode(typeHash, permissionsHash, c.spender, c.permit.nonce, c.permit.deadline));
        }
        return keccak256(abi.encode(typeHash, permissionsHash, c.spender, c.permit.nonce, c.permit.deadline, c.witness));
    }

    function _digestWithType(Case memory c, bytes32 typeHash) private view returns (bytes32) {
        return keccak256(
            bytes.concat(
                hex"1901", _domain(address(target), block.chainid), _structHash(c, typeHash, _permissionsHash(c))
            )
        );
    }

    function _digest(Case memory c) private view returns (bytes32) {
        return _digestWithType(c, _typeHash(c.route));
    }

    function _sign(bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _compact(bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, digest);
        return abi.encodePacked(r, bytes32(uint256(s) | (uint256(v - 27) << 255)));
    }

    function _execute(Case memory c, bytes memory signature) private {
        vm.prank(c.spender);
        if (c.route == 0) {
            target.permitTransferFrom(_single(c), c.details[0], c.owner, signature);
        } else if (c.route == 1) {
            target.permitTransferFrom(c.permit, c.details, c.owner, signature);
        } else if (c.route == 2) {
            target.permitWitnessTransferFrom(
                _single(c), c.details[0], c.owner, c.witness, c.witnessTypeString, signature
            );
        } else {
            target.permitWitnessTransferFrom(c.permit, c.details, c.owner, c.witness, c.witnessTypeString, signature);
        }
    }

    function _assertNonce(Case memory c, bool used) private view {
        uint256 bit = uint256(1) << (c.permit.nonce % 256);
        require((target.nonceBitmap(c.owner, c.permit.nonce / 256) & bit != 0) == used, "nonce state");
    }

    function _expectFailure(Case memory c, bytes memory signature, bytes4 selector) private {
        uint256 beforeBalance = token.balanceOf(c.owner);
        uint256 beforeSecond = secondToken.balanceOf(c.owner);
        uint256 beforeRecipient = token.balanceOf(RECIPIENT);
        uint256 beforeSecondRecipient = secondToken.balanceOf(SECOND_RECIPIENT);
        uint256 beforeWord = target.nonceBitmap(c.owner, c.permit.nonce / 256);
        uint256 beforeCalls = token.calls();
        uint256 beforeSecondCalls = secondToken.calls();
        vm.expectRevert(selector);
        _execute(c, signature);
        require(token.balanceOf(c.owner) == beforeBalance, "failed call debited owner");
        require(secondToken.balanceOf(c.owner) == beforeSecond, "failed call debited second token");
        require(token.balanceOf(RECIPIENT) == beforeRecipient, "failed call paid recipient");
        require(secondToken.balanceOf(SECOND_RECIPIENT) == beforeSecondRecipient, "failed batch paid recipient");
        require(target.nonceBitmap(c.owner, c.permit.nonce / 256) == beforeWord, "failed call changed nonce");
        require(
            token.calls() == beforeCalls && secondToken.calls() == beforeSecondCalls, "failed call kept token state"
        );
    }

    function _expectSuccess(Case memory c, bytes memory signature) private {
        uint256[] memory ownerBalances = new uint256[](c.details.length);
        uint256[] memory recipientBalances = new uint256[](c.details.length);
        uint256[] memory callCounts = new uint256[](c.details.length);
        uint256 beforeWord = target.nonceBitmap(c.owner, c.permit.nonce / 256);
        for (uint256 i; i < c.details.length; ++i) {
            SignatureTransferToken current = SignatureTransferToken(c.permit.permitted[i].token);
            ownerBalances[i] = current.balanceOf(c.owner);
            recipientBalances[i] = current.balanceOf(c.details[i].to);
            callCounts[i] = current.calls();
            current.watchNonce(target, c.owner, c.permit.nonce);
        }
        _execute(c, signature);
        for (uint256 i; i < c.details.length; ++i) {
            SignatureTransferToken current = SignatureTransferToken(c.permit.permitted[i].token);
            require(current.balanceOf(c.owner) == ownerBalances[i] - c.details[i].requestedAmount, "owner debit");
            require(
                current.balanceOf(c.details[i].to) == recipientBalances[i] + c.details[i].requestedAmount,
                "recipient credit"
            );
            require(
                current.calls() == callCounts[i] + (c.details[i].requestedAmount == 0 ? 0 : 1), "transfer call count"
            );
        }
        require(
            target.nonceBitmap(c.owner, c.permit.nonce / 256) == beforeWord | (uint256(1) << (c.permit.nonce % 256)),
            "changed unrelated nonce bits"
        );
        _assertNonce(c, true);
    }

    function testSingleHappyPath() public {
        Case memory c = _case(0);
        _expectSuccess(c, _sign(_digest(c)));
    }

    function testBatchHappyPath() public {
        Case memory c = _case(1);
        _expectSuccess(c, _sign(_digest(c)));
    }

    function testWitnessHappyPath() public {
        Case memory c = _case(2);
        _expectSuccess(c, _sign(_digest(c)));
    }

    function testBatchWitnessHappyPath() public {
        Case memory c = _case(3);
        _expectSuccess(c, _sign(_digest(c)));
    }

    function testCompactSignaturesAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            _expectSuccess(c, _compact(_digest(c)));
        }
    }

    function testSpenderMayChooseRecipientAndAmountWithinPermit() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            c.details[0].to = SPENDER_B;
            c.details[0].requestedAmount = c.permit.permitted[0].amount;
            _expectSuccess(c, signature);
        }
    }

    function testNonceReuseAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            _expectSuccess(c, signature);
            _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
        }
    }

    function testNonceSharedAcrossAllEntryPoints() public {
        Case memory initial = _case(0);
        initial.permit.nonce = 999;
        _expectSuccess(initial, _sign(_digest(initial)));
        for (uint8 route = 1; route < 4; ++route) {
            Case memory c = _case(route);
            c.permit.nonce = initial.permit.nonce;
            _expectFailure(c, _sign(_digest(c)), SignatureTransfer.InvalidNonce.selector);
        }
    }

    function testNonceWordBoundary255And256AndMaximum() public {
        uint256[4] memory nonces = [uint256(255), uint256(256), uint256(254), type(uint256).max];
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            c.permit.nonce = nonces[route];
            bytes memory signature = _sign(_digest(c));
            _expectSuccess(c, signature);
            _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
        }
        require(target.nonceBitmap(owner, 0) == (uint256(1) << 255) | (uint256(1) << 254), "word zero");
        require(target.nonceBitmap(owner, 1) == 1, "word one");
        require(target.nonceBitmap(owner, type(uint256).max / 256) == uint256(1) << 255, "maximum nonce");
    }

    function testWholeWordInvalidationEventAndIsolation() public {
        uint256 word = 17;
        vm.expectEmit(true, false, false, true, address(target));
        emit UnorderedNonceInvalidation(owner, word, type(uint256).max);
        vm.prank(owner);
        target.invalidateUnorderedNonces(word, type(uint256).max);
        require(target.nonceBitmap(owner, word) == type(uint256).max, "whole word not invalidated");
        require(target.nonceBitmap(SPENDER_A, word) == 0, "other owner invalidated");
        for (uint256 bit; bit < 256; ++bit) {
            Case memory c = _case(uint8(bit % 4));
            c.permit.nonce = word * 256 + bit;
            _expectFailure(c, _sign(_digest(c)), SignatureTransfer.InvalidNonce.selector);
        }
        Case memory neighbor = _case(0);
        neighbor.permit.nonce = (word + 1) * 256;
        _expectSuccess(neighbor, _sign(_digest(neighbor)));
    }

    function testInvalidationIsCallerScopedAndOnlyAddsBits() public {
        vm.prank(SPENDER_A);
        target.invalidateUnorderedNonces(0, type(uint256).max);
        Case memory c = _case(0);
        _expectSuccess(c, _sign(_digest(c)));
        vm.prank(owner);
        target.invalidateUnorderedNonces(0, 4);
        vm.prank(owner);
        target.invalidateUnorderedNonces(0, 4);
        vm.prank(owner);
        target.invalidateUnorderedNonces(0, 0);
        require(target.nonceBitmap(owner, 0) == 5, "invalidation cleared or toggled bits");
        c.permit.nonce = 1;
        _expectSuccess(c, _sign(_digest(c)));
        require(target.nonceBitmap(owner, 0) == 7, "adjacent nonce affected");
    }

    function testNonceIsOwnerScoped() public {
        Case memory c = _case(0);
        _expectSuccess(c, _sign(_digest(c)));
        c.owner = vm.addr(OTHER_KEY);
        _fund(c.owner);
        vm.prank(c.owner);
        token.approve(address(target), type(uint256).max);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OTHER_KEY, _digest(c));
        _expectSuccess(c, abi.encodePacked(r, s, v));
    }

    function testDeadlineIsInclusiveAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            c.permit.deadline = NOW;
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testDeadlinePlusOneRevertsWithDeadlineAllEntryPoints() public {
        vm.warp(NOW + 1);
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            c.permit.deadline = NOW;
            bytes memory signature = _sign(_digest(c));
            vm.expectRevert(abi.encodeWithSelector(SignatureTransfer.SignatureExpired.selector, NOW));
            _execute(c, signature);
            _assertNonce(c, false);
        }
        require(token.calls() == 0 && secondToken.calls() == 0, "expired transfer called token");
    }

    function testZeroDeadlineAtZeroTimestamp() public {
        vm.warp(0);
        Case memory c = _case(0);
        c.permit.deadline = 0;
        _expectSuccess(c, _sign(_digest(c)));
    }

    function testSignatureBindsSpenderAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            c.spender = SPENDER_B;
            _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            c.spender = SPENDER_A;
            _expectSuccess(c, signature);
        }
    }

    function testSignatureBindsEveryPermitFieldAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            for (uint8 field; field < 4; ++field) {
                Case memory c = _case(route);
                bytes memory signature = _sign(_digest(c));
                if (field == 0) c.permit.permitted[0].token = address(secondToken);
                if (field == 1) ++c.permit.permitted[0].amount;
                if (field == 2) c.permit.nonce += 100;
                if (field == 3) ++c.permit.deadline;
                _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            }
        }
    }

    function testWrongOwnerAndZeroRecoveredSigner() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(OTHER_KEY, _digest(c));
            _expectFailure(c, abi.encodePacked(r, s, v), SignatureTransfer.InvalidSigner.selector);
            _expectFailure(
                c, abi.encodePacked(bytes32(0), bytes32(0), uint8(27)), SignatureTransfer.InvalidSigner.selector
            );
            c.owner = address(0);
            _expectFailure(
                c, abi.encodePacked(bytes32(0), bytes32(0), uint8(27)), SignatureTransfer.InvalidSigner.selector
            );
        }
    }

    function testInvalidSignatureLengthsAllEntryPoints() public {
        uint256[6] memory lengths = [uint256(0), 1, 32, 63, 66, 96];
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            for (uint256 i; i < lengths.length; ++i) {
                _expectFailure(c, new bytes(lengths[i]), SignatureTransfer.InvalidSignatureLength.selector);
            }
        }
    }

    function testInvalidVAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            (, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, _digest(c));
            _expectFailure(c, abi.encodePacked(r, s, uint8(0)), SignatureTransfer.InvalidSigner.selector);
            _expectFailure(c, abi.encodePacked(r, s, uint8(29)), SignatureTransfer.InvalidSigner.selector);
        }
    }

    function testHighSMalleableSignatureRejectedAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            bytes32 digest = _digest(c);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, digest);
            bytes32 highS = bytes32(CURVE_ORDER - uint256(s));
            uint8 flippedV = v == 27 ? 28 : 27;
            require(uint256(highS) > HALF_ORDER, "not high s");
            require(ecrecover(digest, flippedV, r, highS) == owner, "not a valid malleation");
            _expectFailure(c, abi.encodePacked(r, highS, flippedV), SignatureTransfer.InvalidSigner.selector);
            _expectSuccess(c, abi.encodePacked(r, s, v));
        }
    }

    function testCompactHighSRejected() public {
        Case memory c = _case(0);
        (, bytes32 r,) = vm.sign(OWNER_KEY, _digest(c));
        // This value fits the 255-bit compact s field but exceeds n/2.
        _expectFailure(c, abi.encodePacked(r, bytes32(HALF_ORDER + 1)), SignatureTransfer.InvalidSigner.selector);
    }

    function testAmountAbovePermitRevertsWithMaximumAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            uint256 index = c.details.length - 1;
            c.details[index].requestedAmount = c.permit.permitted[index].amount + 1;
            uint256 beforeBalance = token.balanceOf(owner);
            uint256 beforeCalls = token.calls();
            vm.expectRevert(
                abi.encodeWithSelector(SignatureTransfer.InvalidAmount.selector, c.permit.permitted[index].amount)
            );
            _execute(c, signature);
            _assertNonce(c, false);
            require(token.balanceOf(owner) == beforeBalance && token.calls() == beforeCalls, "partial batch survived");
            c.details[index].requestedAmount = c.permit.permitted[index].amount;
            _expectSuccess(c, signature);
        }
    }

    function testZeroRequestSkipsTokenButConsumesNonceAllEntryPoints() public {
        token.setReturnMode(3);
        secondToken.setReturnMode(3);
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            for (uint256 i; i < c.details.length; ++i) {
                c.details[i].requestedAmount = 0;
            }
            bytes memory signature = _sign(_digest(c));
            _expectSuccess(c, signature);
            _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
        }
    }

    function testZeroPermitAndZeroRequestAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            for (uint256 i; i < c.details.length; ++i) {
                c.permit.permitted[i].amount = 0;
                c.details[i].requestedAmount = 0;
            }
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testZeroRequestStillRequiresValidSignature() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            for (uint256 i; i < c.details.length; ++i) {
                c.details[i].requestedAmount = 0;
            }
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(OTHER_KEY, _digest(c));
            _expectFailure(c, abi.encodePacked(r, s, v), SignatureTransfer.InvalidSigner.selector);
        }
    }

    function testMixedZeroAndNonzeroBatchRequests() public {
        token.setReturnMode(3);
        for (uint8 route = 1; route < 4; route += 2) {
            Case memory c = _case(route);
            c.details[0].requestedAmount = 0;
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testBatchLengthMismatchBothDirections() public {
        for (uint8 route = 1; route < 4; route += 2) {
            for (uint256 length; length < 4; ++length) {
                if (length == 2) continue;
                Case memory c = _case(route);
                bytes memory signature = _sign(_digest(c));
                c.details = new SignatureTransfer.SignatureTransferDetails[](length);
                _expectFailure(c, signature, SignatureTransfer.LengthMismatch.selector);
            }
        }
    }

    function testEmptyBatchHashesEmptyConcatenationAndConsumesNonce() public {
        for (uint8 route = 1; route < 4; route += 2) {
            Case memory c = _case(route);
            c.permit.permitted = new SignatureTransfer.TokenPermissions[](0);
            c.details = new SignatureTransfer.SignatureTransferDetails[](0);
            require(_permissionsHash(c) == keccak256(hex""), "wrong empty array hash");
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(OTHER_KEY, _digest(c));
            _expectFailure(c, abi.encodePacked(r, s, v), SignatureTransfer.InvalidSigner.selector);
            bytes memory signature = _sign(_digest(c));
            _expectSuccess(c, signature);
            _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
        }
    }

    function testOneElementBatchUsesBatchTypeAndArrayHash() public {
        for (uint8 route = 1; route < 4; route += 2) {
            Case memory c = _case(route - 1);
            // Even a one-element batch has its own primary type and hashes the
            // concatenation of element hashes instead of using the element directly.
            bytes memory singleSignature = _sign(_digest(c));
            c.route = route;
            _expectFailure(c, singleSignature, SignatureTransfer.InvalidSigner.selector);
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testBatchWithRepeatedTokenAndRecipient() public {
        for (uint8 route = 1; route < 4; route += 2) {
            Case memory c = _case(route);
            c.permit.permitted[1].token = address(token);
            c.details[1].to = RECIPIENT;
            uint256 beforeOwner = token.balanceOf(owner);
            uint256 beforeRecipient = token.balanceOf(RECIPIENT);
            uint256 beforeCalls = token.calls();
            token.watchNonce(target, owner, c.permit.nonce);
            bytes memory signature = _sign(_digest(c));
            _execute(c, signature);
            require(token.balanceOf(owner) == beforeOwner - 150, "duplicate-token owner debit");
            require(token.balanceOf(RECIPIENT) == beforeRecipient + 150, "duplicate-token recipient credit");
            require(token.calls() == beforeCalls + 2, "duplicate-token transfers");
            require(secondToken.calls() == 0, "unsigned token called");
            _assertNonce(c, true);
            _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
        }
    }

    function testMaximumAmountNonceAndDeadline() public {
        Case memory c = _case(0);
        c.permit.permitted[0].amount = type(uint256).max;
        c.details[0].requestedAmount = type(uint256).max;
        c.permit.nonce = type(uint256).max;
        c.permit.deadline = type(uint256).max;
        token.setBalance(owner, type(uint256).max);
        bytes memory signature = _sign(_digest(c));
        _expectSuccess(c, signature);
        _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
    }

    function testBatchSignatureBindsOrderLengthAndEveryElement() public {
        for (uint8 route = 1; route < 4; route += 2) {
            for (uint8 mutation; mutation < 4; ++mutation) {
                Case memory c = _case(route);
                bytes memory signature = _sign(_digest(c));
                if (mutation == 0) {
                    SignatureTransfer.TokenPermissions memory first =
                        SignatureTransfer.TokenPermissions(c.permit.permitted[0].token, c.permit.permitted[0].amount);
                    c.permit.permitted[0] = c.permit.permitted[1];
                    c.permit.permitted[1] = first;
                } else if (mutation == 1) {
                    c.permit.permitted[1].token = address(token);
                } else if (mutation == 2) {
                    ++c.permit.permitted[1].amount;
                } else {
                    SignatureTransfer.TokenPermissions[] memory shortened = new SignatureTransfer.TokenPermissions[](1);
                    shortened[0] = c.permit.permitted[0];
                    c.permit.permitted = shortened;
                    SignatureTransfer.SignatureTransferDetails[] memory details =
                        new SignatureTransfer.SignatureTransferDetails[](1);
                    details[0] = c.details[0];
                    c.details = details;
                }
                _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            }
        }
    }

    function testArrayHashRejectsAbiArrayEncodingAndLengthPrefix() public {
        for (uint8 route = 1; route < 4; route += 2) {
            Case memory c = _case(route);
            bytes32[] memory elementHashes = new bytes32[](2);
            for (uint256 i; i < 2; ++i) {
                elementHashes[i] =
                    keccak256(abi.encode(TOKEN_TYPE, c.permit.permitted[i].token, c.permit.permitted[i].amount));
            }
            bytes32[3] memory wrongArrayHashes = [
                keccak256(abi.encode(c.permit.permitted)),
                keccak256(abi.encode(elementHashes)),
                keccak256(abi.encodePacked(uint256(2), elementHashes[0], elementHashes[1]))
            ];
            for (uint256 i; i < wrongArrayHashes.length; ++i) {
                bytes32 digest = keccak256(
                    bytes.concat(
                        hex"1901",
                        _domain(address(target), block.chainid),
                        _structHash(c, _typeHash(route), wrongArrayHashes[i])
                    )
                );
                _expectFailure(c, _sign(digest), SignatureTransfer.InvalidSigner.selector);
            }
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testNoReturnTokensAllEntryPoints() public {
        token.setReturnMode(1);
        secondToken.setReturnMode(1);
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testFalseRevertingAndMalformedTokensRollBackAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            SignatureTransferToken failing = route % 2 == 0 ? token : secondToken;
            for (uint8 mode = 2; mode <= 5; ++mode) {
                failing.setReturnMode(mode);
                _expectFailure(c, signature, SignatureTransfer.TransferFromFailed.selector);
            }
            failing.setReturnMode(0);
            _expectSuccess(c, signature);
        }
    }

    function testNoCodeTokenRejectedForNonzeroAndZeroAmountsAllEntryPoints() public {
        for (uint8 route; route < 4; ++route) {
            for (uint256 amount; amount <= 1; ++amount) {
                Case memory c = _case(route);
                uint256 index = c.permit.permitted.length - 1;
                c.permit.permitted[index].token = address(0xdead);
                c.details[index].requestedAmount = amount;
                _expectFailure(c, _sign(_digest(c)), SignatureTransfer.TransferFromFailed.selector);
                c.permit.permitted[index].token = address(0);
                _expectFailure(c, _sign(_digest(c)), SignatureTransfer.TransferFromFailed.selector);
            }
        }
    }

    function testAllowanceAndBalanceFailuresRollBackNonce() public {
        Case memory c = _case(0);
        bytes memory signature = _sign(_digest(c));
        vm.prank(owner);
        token.approve(address(target), 59);
        _expectFailure(c, signature, SignatureTransfer.TransferFromFailed.selector);
        vm.prank(owner);
        token.approve(address(target), 60);
        token.setBalance(owner, 59);
        _expectFailure(c, signature, SignatureTransfer.TransferFromFailed.selector);
        token.setBalance(owner, 60);
        _expectSuccess(c, signature);
        require(token.allowance(owner, address(target)) == 0, "transfer did not spend allowance");
    }

    function testERC1271ChecksExactDigestBeforeAnyTransferAllEntryPoints() public {
        SignatureTransferWallet wallet = new SignatureTransferWallet(target, token, secondToken);
        _fund(address(wallet));
        // An arbitrary-length contract signature must bypass EOA signature parsing.
        bytes memory signature = hex"c0ffee";
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            c.owner = address(wallet);
            wallet.configure(_digest(c), signature, c.permit.nonce, 0);
            _expectSuccess(c, signature);
        }
    }

    function testERC1271WrongMagicRevertAndMalformedReturnAllEntryPoints() public {
        SignatureTransferWallet wallet = new SignatureTransferWallet(target, token, secondToken);
        _fund(address(wallet));
        bytes memory signature = hex"c0ffee";
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            c.owner = address(wallet);
            for (uint8 mode = 1; mode <= 4; ++mode) {
                wallet.configure(_digest(c), signature, c.permit.nonce, mode);
                _expectFailure(c, signature, SignatureTransfer.InvalidContractSignature.selector);
            }
            wallet.configure(_digest(c), signature, c.permit.nonce, 0);
            _expectSuccess(c, signature);
        }
    }

    function testERC1271RejectsChangedDigestAndSignature() public {
        SignatureTransferWallet wallet = new SignatureTransferWallet(target, token, secondToken);
        _fund(address(wallet));
        for (uint8 route; route < 4; ++route) {
            Case memory c = _case(route);
            c.owner = address(wallet);
            bytes memory signature = hex"c0ffee";
            wallet.configure(_digest(c), signature, c.permit.nonce, 0);
            _expectFailure(c, hex"c0ffef", SignatureTransfer.InvalidContractSignature.selector);
            c.spender = SPENDER_B;
            _expectFailure(c, signature, SignatureTransfer.InvalidContractSignature.selector);
            c.spender = SPENDER_A;
            _expectSuccess(c, signature);
        }
    }

    function testReentrantTokenCannotReuseNonce() public {
        Case memory c = _case(0);
        c.spender = address(token);
        bytes memory signature = _sign(_digest(c));
        token.setReentry(
            abi.encodeWithSignature(
                "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)",
                _single(c),
                c.details[0],
                c.owner,
                signature
            )
        );
        _expectSuccess(c, signature);
        require(token.reentryAttempted(), "callback not exercised");
        require(token.reentryError() == SignatureTransfer.InvalidNonce.selector, "callback rejected for wrong reason");
        require(token.calls() == 1, "token transferred more than once");
    }

    function testDomainMatchesEIP712AndTracksChainChanges() public {
        uint256 originalChain = block.chainid;
        bytes32 originalDomain = _domain(address(target), originalChain);
        require(target.DOMAIN_SEPARATOR() == originalDomain, "initial domain");
        uint256 newChain = originalChain == 1 ? 2 : 1;
        vm.chainId(newChain);
        require(target.DOMAIN_SEPARATOR() == _domain(address(target), newChain), "stale domain after fork");
        require(target.DOMAIN_SEPARATOR() != originalDomain, "chain not bound");
        vm.chainId(originalChain);
        require(target.DOMAIN_SEPARATOR() == originalDomain, "cached domain after returning to original chain");
        SignatureTransfer other = new SignatureTransfer();
        require(other.DOMAIN_SEPARATOR() == _domain(address(other), originalChain), "other deployment domain");
        require(other.DOMAIN_SEPARATOR() != originalDomain, "verifying contract not bound");
    }

    function testSignatureCannotReplayAcrossChainsAllEntryPoints() public {
        uint256 originalChain = block.chainid;
        uint256 newChain = originalChain == 1 ? 2 : 1;
        for (uint8 route; route < 4; ++route) {
            vm.chainId(originalChain);
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            vm.chainId(newChain);
            _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testSignatureCannotReplayAcrossDeployments() public {
        Case memory c = _case(0);
        bytes memory signature = _sign(_digest(c));
        SignatureTransfer original = target;
        target = new SignatureTransfer();
        vm.prank(owner);
        token.approve(address(target), type(uint256).max);
        _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
        _expectSuccess(c, _sign(_digest(c)));
        target = original;
        _expectSuccess(c, signature);
    }

    function testDomainWithVersionCannotAuthorize() public {
        Case memory c = _case(0);
        bytes32 wrongDomain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Permit2"),
                keccak256("1"),
                block.chainid,
                address(target)
            )
        );
        bytes32 digest =
            keccak256(bytes.concat(hex"1901", wrongDomain, _structHash(c, SINGLE_TYPE, _permissionsHash(c))));
        _expectFailure(c, _sign(digest), SignatureTransfer.InvalidSigner.selector);
    }

    function testWitnessTypeAndValueCannotBeSubstituted() public {
        for (uint8 route = 2; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory signature = _sign(_digest(c));
            bytes32 originalWitness = c.witness;
            c.witness = bytes32(uint256(c.witness) ^ 1);
            _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            c.witness = originalWitness;
            c.witnessTypeString = OTHER_WITNESS_SUFFIX;
            _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            c.witnessTypeString = WITNESS_SUFFIX;
            _expectSuccess(c, signature);
        }
    }

    function testPlainSignatureNeverPassesWitnessPathAndViceVersa() public {
        for (uint8 route = 2; route < 4; ++route) {
            Case memory c = _case(route);
            bytes memory witnessSignature = _sign(_digest(c));
            c.route -= 2;
            bytes memory plainSignature = _sign(_digest(c));
            _expectFailure(c, witnessSignature, SignatureTransfer.InvalidSigner.selector);
            c.route += 2;
            _expectFailure(c, plainSignature, SignatureTransfer.InvalidSigner.selector);
            _expectSuccess(c, witnessSignature);
        }
    }

    function testWitnessInjectionHasDistinctDigestAndCannotReuseLegitimateSignatures() public {
        for (uint8 route = 2; route < 4; ++route) {
            Case memory c = _case(route);
            bytes32 injectedType = route == 2
                ? keccak256(
                    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Mock witness)Mock(uint256 a)TokenPermissions(address token,uint256 amount)X("
                )
                : keccak256(
                    "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mock witness)Mock(uint256 a)TokenPermissions(address token,uint256 amount)X("
                );
            bytes32 injectedDigest = _digestWithType(c, injectedType);
            c.witnessTypeString = INJECTED_SUFFIX;
            // Check all four legitimate message families. No parser is expected to
            // reject the suffix: security comes from signing its exact type hash.
            for (uint8 legitimateRoute; legitimateRoute < 4; ++legitimateRoute) {
                c.route = legitimateRoute;
                bytes32 legitimateDigest = _digest(c);
                require(injectedDigest != legitimateDigest, "injected digest collides with legitimate digest");
                bytes memory signature = _sign(legitimateDigest);
                c.route = route;
                _expectFailure(c, signature, SignatureTransfer.InvalidSigner.selector);
            }
            // The converse must also fail: signing the injected bytes cannot authorize
            // a legitimate witness message.
            c.witnessTypeString = WITNESS_SUFFIX;
            _expectFailure(c, _sign(injectedDigest), SignatureTransfer.InvalidSigner.selector);
        }
    }

    function testWitnessDependentTypesMustFollowPrimaryInCanonicalOrder() public {
        for (uint8 route = 2; route < 4; ++route) {
            Case memory c = _case(route);
            bytes32 wronglyOrderedType = route == 2
                ? keccak256(
                    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Mock witness)TokenPermissions(address token,uint256 amount)Mock(uint256 a)"
                )
                : keccak256(
                    "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Mock witness)TokenPermissions(address token,uint256 amount)Mock(uint256 a)"
                );
            _expectFailure(c, _sign(_digestWithType(c, wronglyOrderedType)), SignatureTransfer.InvalidSigner.selector);
            _expectSuccess(c, _sign(_digest(c)));
        }
    }

    function testWitnessTypeAfterTokenPermissionsInAlphabeticalOrder() public {
        for (uint8 route = 2; route < 4; ++route) {
            Case memory c = _case(route);
            c.witness = keccak256(abi.encode(keccak256("Zulu(uint256 value)"), uint256(42)));
            c.witnessTypeString = "Zulu witness)TokenPermissions(address token,uint256 amount)Zulu(uint256 value)";
            bytes32 fullType = route == 2
                ? keccak256(
                    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Zulu witness)TokenPermissions(address token,uint256 amount)Zulu(uint256 value)"
                )
                : keccak256(
                    "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Zulu witness)TokenPermissions(address token,uint256 amount)Zulu(uint256 value)"
                );
            _expectSuccess(c, _sign(_digestWithType(c, fullType)));
        }
    }

    function testFuzzAmountNonceAndDeadline(
        uint256 amount,
        uint256 requestSeed,
        uint256 nonce,
        uint256 deadline,
        uint8 routeSeed
    ) public {
        Case memory c = _case(routeSeed % 4);
        c.permit.nonce = nonce;
        c.permit.deadline = deadline;
        uint256 requested = amount == type(uint256).max ? requestSeed : requestSeed % (amount + 1);
        c.permit.permitted[0].amount = amount;
        c.details[0].requestedAmount = requested;
        token.setBalance(owner, amount);
        vm.warp(deadline); // Includes zero and the entire uint256 deadline range.
        bytes memory signature = _sign(_digest(c));
        _expectSuccess(c, signature);
        _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
    }

    function testFuzzExpiredPermit(uint256 deadlineSeed, uint256 nonce, uint8 routeSeed) public {
        uint256 deadline = deadlineSeed == type(uint256).max ? deadlineSeed - 1 : deadlineSeed;
        Case memory c = _case(routeSeed % 4);
        c.permit.deadline = deadline;
        c.permit.nonce = nonce;
        bytes memory signature = _sign(_digest(c));
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(SignatureTransfer.SignatureExpired.selector, deadline));
        _execute(c, signature);
        _assertNonce(c, false);
        require(token.calls() == 0 && secondToken.calls() == 0, "expired permit moved funds");
    }

    function testFuzzAmountAbovePermit(uint256 amountSeed, uint256 nonce, uint8 routeSeed) public {
        uint256 amount = amountSeed == type(uint256).max ? amountSeed - 1 : amountSeed;
        Case memory c = _case(routeSeed % 4);
        uint256 index = c.details.length - 1;
        c.permit.permitted[index].amount = amount;
        c.details[index].requestedAmount = amount + 1;
        c.permit.nonce = nonce;
        bytes memory signature = _sign(_digest(c));
        vm.expectRevert(abi.encodeWithSelector(SignatureTransfer.InvalidAmount.selector, amount));
        _execute(c, signature);
        _assertNonce(c, false);
        require(token.balanceOf(owner) == INITIAL_BALANCE, "partial batch moved first token");
        require(token.calls() == 0 && secondToken.calls() == 0, "failed request kept token state");
    }

    function testFuzzInvalidationMatchesBitMath(uint256 nonce, uint256 mask, uint8 routeSeed) public {
        Case memory c = _case(routeSeed % 4);
        c.permit.nonce = nonce;
        uint256 word = nonce / 256;
        vm.prank(owner);
        target.invalidateUnorderedNonces(word, mask);
        require(target.nonceBitmap(owner, word) == mask, "invalidation word");
        bytes memory signature = _sign(_digest(c));
        uint256 bit = uint256(1) << (nonce % 256);
        if (mask & bit != 0) _expectFailure(c, signature, SignatureTransfer.InvalidNonce.selector);
        else _expectSuccess(c, signature);
        require(target.nonceBitmap(owner, word) == mask | bit, "nonce bitmap arithmetic");
        require(target.nonceBitmap(SPENDER_A, word) == 0, "nonce owner isolation");
    }
}
