// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {AQueryProofExecutor} from "@rarimo/passport-contracts/sdk/AQueryProofExecutor.sol";

import {IPoseidonSMT} from "@rarimo/passport-contracts/interfaces/state/IPoseidonSMT.sol";

import {Date2Time} from "@rarimo/passport-contracts/utils/Date2Time.sol";

/**
 * @title PublicSignalsTD1Builder23 Library.
 * @notice Local copy with PROOF_SIGNALS_COUNT = 23 to match our INID circuit.
 *
 * @dev Signal indices (0-22) for INID circuit (queryIdentity_inid_ca):
 *      IMPORTANT: These differ from standard TD1 docs! Verified from actual circuit output.
 *
 *   0  - nullifier
 *   1  - birthDate
 *   2  - expirationDate
 *   3  - name
 *   4  - nationality
 *   5  - sex              ← INID circuit actual (NOT citizenship as in some docs)
 *   6  - citizenship      ← INID circuit actual (ISO 3166-1 alpha-3)
 *   7  - documentNumberHash
 *   8  - personalNumberHash
 *   9  - eventId          (NO documentType in our 23-signal variant)
 *   10 - eventData
 *   11 - idStateRoot
 *   12 - selector
 *   13 - currentDate
 *   14 - timestampLowerbound
 *   15 - timestampUpperbound
 *   16 - identityCounterLowerbound
 *   17 - identityCounterUpperbound
 *   18 - birthDateLowerbound
 *   19 - birthDateUpperbound
 *   20 - expirationDateLowerbound
 *   21 - expirationDateUpperbound
 *   22 - citizenshipMask
 */
library PublicSignalsTD1Builder23 {
    uint256 public constant PROOF_SIGNALS_COUNT = 23;
    uint256 public constant ZERO_DATE = 0x303030303030;

    // bytes32(uint256(keccak256("rarimo.contract.AQueryProofExecutor")) - 1)
    bytes32 private constant A_BUILDER_STORAGE =
        0x3844f6f56a171c93056bdfb3ce2525778ef493f53ef90b0283983867a69d2128;

    error InvalidDate(uint256 parsedTimestamp, uint256 currentTimestamp);
    error InvalidRegistrationRoot(address registrationSMT, bytes32 registrationRoot);

    function newPublicSignalsBuilder(
        uint256 selector_,
        uint256 nullifier_
    ) internal pure returns (uint256 dataPointer_) {
        uint256[] memory pubSignals_ = new uint256[](PROOF_SIGNALS_COUNT);

        assembly {
            dataPointer_ := pubSignals_

            // 32 + 0 = 32
            mstore(add(dataPointer_, 32), nullifier_)
            // selector at index 12 (TD3/INID style) -> 32 + 12*32 = 416
            mstore(add(dataPointer_, 416), selector_)

            // currentDate_ at index 13 (TD3/INID style) -> 32 + 13*32 = 448
            mstore(add(dataPointer_, 448), ZERO_DATE)
            // birthDateLowerbound_ at index 18 (TD3/INID style) -> 32 + 18*32 = 608
            mstore(add(dataPointer_, 608), ZERO_DATE)
            // birthDateUpperbound_ at index 19 (TD3/INID style) -> 32 + 19*32 = 640
            mstore(add(dataPointer_, 640), ZERO_DATE)
            // expirationDateLowerbound_ at index 20 (TD3/INID style) -> 32 + 20*32 = 672
            mstore(add(dataPointer_, 672), ZERO_DATE)
            // expirationDateUpperbound_ at index 21 (TD3/INID style) -> 32 + 21*32 = 704
            mstore(add(dataPointer_, 704), ZERO_DATE)
        }
    }

    /**
     * @notice Sets the name (first name, index 3) in the public signals array.
     */
    function withName(uint256 dataPointer_, uint256 name_) internal pure {
        assembly {
            // 32 + 3 * 32 = 128
            mstore(add(dataPointer_, 128), name_)
        }
    }

    /**
     * @notice Sets the birthDate (index 1) in the public signals array.
     */
    function withBirthDate(uint256 dataPointer_, uint256 birthDate_) internal pure {
        assembly {
            // 32 + 1 * 32 = 64
            mstore(add(dataPointer_, 64), birthDate_)
        }
    }

    /**
     * @notice Sets the expirationDate (index 2) in the public signals array.
     */
    function withExpirationDate(uint256 dataPointer_, uint256 expirationDate_) internal pure {
        assembly {
            // 32 + 2 * 32 = 96
            mstore(add(dataPointer_, 96), expirationDate_)
        }
    }

    /**
     * @notice Sets the nationality (index 4) in the public signals array.
     */
    function withNationality(uint256 dataPointer_, uint256 nationality_) internal pure {
        assembly {
            // 32 + 4 * 32 = 160
            mstore(add(dataPointer_, 160), nationality_)
        }
    }

    /**
     * @notice Sets the citizenship (index 6) in the public signals array.
     * @dev IMPORTANT: The INID circuit (queryIdentity_inid_ca) outputs citizenship at index 6,
     *      NOT index 5 as stated in standard TD1 docs. Verified from mobile app logs:
     *      pub_signals[5] = 0x0 (zeros), pub_signals[6] = 0x4952 (IR citizenship)
     */
    function withCitizenship(uint256 dataPointer_, uint256 citizenship_) internal pure {
        assembly {
            // 32 + 6 * 32 = 224 (citizenship at index 6 - INID circuit actual output)
            mstore(add(dataPointer_, 224), citizenship_)
        }
    }

    /**
     * @notice Sets the sex (index 5) in the public signals array.
     * @dev IMPORTANT: The INID circuit outputs sex at index 5 (not index 6).
     */
    function withSex(uint256 dataPointer_, uint256 sex_) internal pure {
        assembly {
            // 32 + 5 * 32 = 192 (sex at index 5 - INID circuit actual output)
            mstore(add(dataPointer_, 192), sex_)
        }
    }

    /**
     * @notice Sets the documentNumberHash (index 7) in the public signals array.
     */
    function withDocumentNumberHash(
        uint256 dataPointer_,
        uint256 documentNumberHash_
    ) internal pure {
        assembly {
            // 32 + 7 * 32 = 256
            mstore(add(dataPointer_, 256), documentNumberHash_)
        }
    }

    /**
     * @notice Sets the personalNumberHash (index 8) in the public signals array.
     */
    function withPersonalNumberHash(
        uint256 dataPointer_,
        uint256 personalNumberHash_
    ) internal pure {
        assembly {
            // 32 + 8 * 32 = 288
            mstore(add(dataPointer_, 288), personalNumberHash_)
        }
    }

    // NOTE: No documentType in INID/TD3 layout - signals continue directly to eventId

    /**
     * @notice Sets the eventId (index 9) and eventData (index 10) in the public signals array.
     * @dev TD3/INID layout: eventId at 9, eventData at 10 (shifted from TD1's 10, 11)
     */
    function withEventIdAndData(
        uint256 dataPointer_,
        uint256 eventId_,
        uint256 eventData_
    ) internal pure {
        assembly {
            // 32 + 9 * 32 = 320 (was 352 in TD1 layout)
            mstore(add(dataPointer_, 320), eventId_)
            // 32 + 10 * 32 = 352 (was 384 in TD1 layout)
            mstore(add(dataPointer_, 352), eventData_)
        }
    }

    /**
     * @notice Sets the idStateRoot (index 11) in the public signals array.
     * @dev TD3/INID layout: idStateRoot at 11 (shifted from TD1's 12)
     */
    function withIdStateRoot(uint256 dataPointer_, bytes32 idStateRoot_) internal view {
        AQueryProofExecutor.AExecutorStorage storage $ = getABuilderStorage();

        if (!IPoseidonSMT($.registrationSMT).isRootValid(idStateRoot_)) {
            revert InvalidRegistrationRoot($.registrationSMT, idStateRoot_);
        }

        assembly {
            // 32 + 11 * 32 = 384 (was 416 in TD1 layout)
            mstore(add(dataPointer_, 384), idStateRoot_)
        }
    }

    /**
     * @notice Sets the selector (index 12) in the public signals array.
     * @dev TD3/INID layout: selector at 12 (shifted from TD1's 13)
     */
    function withSelector(uint256 dataPointer_, uint256 selector_) internal pure {
        assembly {
            // 32 + 12 * 32 = 416 (was 448 in TD1 layout)
            mstore(add(dataPointer_, 416), selector_)
        }
    }

    /**
     * @notice Sets the currentDate (index 13) in the public signals array.
     * @dev TD3/INID layout: currentDate at 13 (shifted from TD1's 14)
     *      This matches the app code which passes pub_signals[13] as currentDate.
     */
    function withCurrentDate(
        uint256 dataPointer_,
        uint256 currentDate_,
        uint256 timeBound_
    ) internal view {
        uint256 parsedTimestamp_ = Date2Time.timestampFromDate(currentDate_);

        if (!validateDate(parsedTimestamp_, timeBound_)) {
            revert InvalidDate(parsedTimestamp_, block.timestamp);
        }

        assembly {
            // 32 + 13 * 32 = 448 (was 480 in TD1 layout)
            mstore(add(dataPointer_, 448), currentDate_)
        }
    }

    /**
     * @notice Sets timestampLowerbound (index 14) and timestampUpperbound (index 15).
     * @dev TD3/INID layout: shifted from TD1's 15, 16
     */
    function withTimestampLowerboundAndUpperbound(
        uint256 dataPointer_,
        uint256 timestampLowerbound_,
        uint256 timestampUpperbound_
    ) internal pure {
        assembly {
            // 32 + 14 * 32 = 480 (was 512 in TD1 layout)
            mstore(add(dataPointer_, 480), timestampLowerbound_)
            // 32 + 15 * 32 = 512 (was 544 in TD1 layout)
            mstore(add(dataPointer_, 512), timestampUpperbound_)
        }
    }

    /**
     * @notice Sets identityCounterLowerbound (index 16) and identityCounterUpperbound (index 17).
     * @dev TD3/INID layout: shifted from TD1's 17, 18
     */
    function withIdentityCounterLowerbound(
        uint256 dataPointer_,
        uint256 identityCounterLowerbound_,
        uint256 identityCounterUpperbound_
    ) internal pure {
        assembly {
            // 32 + 16 * 32 = 544 (was 576 in TD1 layout)
            mstore(add(dataPointer_, 544), identityCounterLowerbound_)
            // 32 + 17 * 32 = 576 (was 608 in TD1 layout)
            mstore(add(dataPointer_, 576), identityCounterUpperbound_)
        }
    }

    /**
     * @notice Sets birthDateLowerbound (index 18) and birthDateUpperbound (index 19).
     * @dev TD3/INID layout: shifted from TD1's 19, 20
     */
    function withBirthDateLowerboundAndUpperbound(
        uint256 dataPointer_,
        uint256 birthDateLowerbound_,
        uint256 birthDateUpperbound_
    ) internal pure {
        assembly {
            // 32 + 18 * 32 = 608 (was 640 in TD1 layout)
            mstore(add(dataPointer_, 608), birthDateLowerbound_)
            // 32 + 19 * 32 = 640 (was 672 in TD1 layout)
            mstore(add(dataPointer_, 640), birthDateUpperbound_)
        }
    }

    /**
     * @notice Sets expirationDateLowerbound (index 20) and expirationDateUpperbound (index 21).
     * @dev TD3/INID layout: shifted from TD1's 21, 22
     */
    function withExpirationDateLowerboundAndUpperbound(
        uint256 dataPointer_,
        uint256 expirationDateLowerbound_,
        uint256 expirationDateUpperbound_
    ) internal pure {
        assembly {
            // 32 + 20 * 32 = 672 (was 704 in TD1 layout)
            mstore(add(dataPointer_, 672), expirationDateLowerbound_)
            // 32 + 21 * 32 = 704 (was 736 in TD1 layout)
            mstore(add(dataPointer_, 704), expirationDateUpperbound_)
        }
    }

    /**
     * @notice Sets citizenshipMask (index 22) in the public signals array.
     * @dev TD3/INID layout: citizenshipMask is now included at index 22
     */
    function withCitizenshipMask(uint256 dataPointer_, uint256 citizenshipMask_) internal pure {
        assembly {
            // 32 + 22 * 32 = 736
            mstore(add(dataPointer_, 736), citizenshipMask_)
        }
    }

    /**
     * @notice Converts the public signals array to a uint256 array.
     */
    function buildAsUintArray(
        uint256 dataPointer_
    ) internal pure returns (uint256[] memory pubSignals_) {
        assembly {
            pubSignals_ := dataPointer_
        }
    }

    /**
     * @notice Converts the public signals array to a bytes32 array.
     */
    function buildAsBytesArray(
        uint256 dataPointer_
    ) internal pure returns (bytes32[] memory pubSignals_) {
        assembly {
            pubSignals_ := dataPointer_
        }
    }

    /**
     * @notice Validates the date by checking if it is within a timeBound_ range of the current block timestamp.
     */
    function validateDate(
        uint256 parsedTimestamp_,
        uint256 timeBound_
    ) internal view returns (bool) {
        return
            parsedTimestamp_ > block.timestamp - timeBound_ &&
            parsedTimestamp_ < block.timestamp + timeBound_;
    }

    /**
     * @notice Retrieves the AQueryProofExecutor.ABuilderStorage storage reference.
     */
    function getABuilderStorage()
        private
        pure
        returns (AQueryProofExecutor.AExecutorStorage storage $)
    {
        assembly {
            $.slot := A_BUILDER_STORAGE
        }
    }
}
