// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IPoseidonSMT} from "@rarimo/passport-contracts/interfaces/state/IPoseidonSMT.sol";
import {INoirVerifier} from "@rarimo/passport-contracts/interfaces/verifiers/INoirVerifier.sol";
// Use local 23-signal version to match our INID circuit (upstream uses 24)
import {PublicSignalsTD1Builder23} from "../lib/PublicSignalsTD1Builder23.sol";

import {BaseVoting} from "./BaseVoting.sol";

import {ProposalsState} from "../state/ProposalsState.sol";

/// @title IDCardVoting
/// @notice Voting contract for INID (Iranian National ID) cards using Noir ZK proofs
/// @dev Uses a 238-entry lookup table for citizenship mask computation to match the INID circuit
contract IDCardVoting is BaseVoting {
    using PublicSignalsTD1Builder23 for uint256;

    error InvalidNoirProof23(bytes32[] pubSignals, bytes zkPoints);

    uint256 public constant IDENTITY_LIMIT = type(uint32).max;

    /**
     * @dev Extended user data for INID circuit (queryIdentity_inid_ca).
     *      Adds personalNumber (signal[8]) which the INID circuit outputs when
     *      selector_bits[1] = 1 (bit 16 of selector). The contract must include
     *      this value in the public signals for the proof to verify.
     *      
     *      We use a separate struct from BaseVoting.UserData to avoid breaking
     *      BioPassportVoting which uses the 3-field struct.
     */
    struct INIDUserData {
        uint256 nullifier;
        uint256 citizenship;
        uint256 identityCreationTimestamp;
        uint256 personalNumber;
    }

    /**
     * @dev INID circuit uses a fixed 238-entry lookup table for citizenship mask.
     * This mapping converts 2-letter country codes (as uint256, e.g., 0x4952 = "IR") to their bit index.
     * The bit index is the position in the circuit's bitmask (0-237).
     *
     * Key countries:
     * - IR (0x4952 = 18770) → index 101
     * - DE (0x4445 = 17477) → index 62
     * - US (0x5553 = 21843) → index 217
     *
     * This mapping is populated in the initializer from the INID_COUNTRY_CODES array.
     */
    mapping(uint256 => uint256) public countryCodeToBitIndex;
    
    /// @dev Flag indicating if the lookup table has been initialized
    bool public lookupTableInitialized;

    function __IDCardVoting_init(
        address registrationSMT_,
        address proposalsState_,
        address votingVerifier_
    ) external initializer {
        __BaseVoting_init(registrationSMT_, proposalsState_, votingVerifier_);
    }
    
    /**
     * @notice Initialize the country code to bit index lookup table
     * @dev This must be called after deployment to set up the 238-entry mapping.
     *      Each entry maps a 2-letter country code (as uint256) to its bit index.
     *      Can only be called once.
     * @param countryCodes_ Array of 238 country codes in order (index 0 = bit 0, etc.)
     */
    function initializeLookupTable(uint256[] calldata countryCodes_) external {
        require(!lookupTableInitialized, "IDCardVoting: lookup table already initialized");
        require(countryCodes_.length == 238, "IDCardVoting: must provide exactly 238 country codes");
        
        for (uint256 i = 0; i < countryCodes_.length; i++) {
            countryCodeToBitIndex[countryCodes_[i]] = i;
        }
        lookupTableInitialized = true;
    }
    
    /**
     * @notice Computes a citizenship bitmask from an array of allowed country codes
     * @dev Each country code (e.g., 0x4952 for "IR") is converted to a bit position
     *      using the lookup table initialized in initializeLookupTable().
     *      This matches the INID circuit's citizenship mask computation which uses
     *      a 238-entry lookup table (not modular arithmetic).
     * @param citizenshipWhitelist_ Array of country codes (as uint256)
     * @return mask_ Bitmask with bits set for each allowed country
     */
    function _computeCitizenshipMask(uint256[] memory citizenshipWhitelist_) internal view returns (uint256 mask_) {
        require(lookupTableInitialized, "IDCardVoting: lookup table not initialized");
        
        for (uint256 i = 0; i < citizenshipWhitelist_.length; i++) {
            uint256 countryCode = citizenshipWhitelist_[i];
            uint256 bitIndex = countryCodeToBitIndex[countryCode];
            // Note: bitIndex 0 is valid, so we can't check for 0 to detect missing entries
            // The lookup table must be complete for all supported countries
            mask_ |= (1 << bitIndex);
        }
        return mask_;
    }

    function _beforeVerify(bytes32, uint256, bytes memory userPayload_) internal view override {
        (uint256 proposalId_, , INIDUserData memory userData_) = abi.decode(
            userPayload_,
            (uint256, uint256[], INIDUserData)
        );

        ProposalRules memory proposalRules_ = getProposalRules(proposalId_);

        require(
            _validateCitizenship(proposalRules_.citizenshipWhitelist, userData_.citizenship),
            "Voting: citizenship is not whitelisted"
        );
    }

    function _afterVerify(bytes32, uint256, bytes memory userPayload_) internal override {
        (uint256 proposalId_, uint256[] memory vote_, INIDUserData memory userData_) = abi.decode(
            userPayload_,
            (uint256, uint256[], INIDUserData)
        );

        ProposalsState(proposalsState).vote(proposalId_, userData_.nullifier, vote_);
    }

    function _buildPublicSignalsTD1(
        bytes32,
        uint256 currentDate_,
        bytes memory userPayload_
    ) internal view override returns (uint256) {
        (uint256 proposalId_, uint256[] memory vote_, INIDUserData memory userData_) = abi.decode(
            userPayload_,
            (uint256, uint256[], INIDUserData)
        );

        uint256 proposalEventId = ProposalsState(proposalsState).getProposalEventId(proposalId_);
        ProposalRules memory proposalRules_ = getProposalRules(proposalId_);

        /**
         * By default we check that the identity is created before the identityCreationTimestampUpperBound (proposal start)
         *
         * ROOT_VALIDITY is subtracted to address the issue with multiaccounts if they are created right before the voting.
         * The registration root will still be valid and a user may bring 100 roots to vote 100 times.
         */
        uint256 identityCreationTimestampUpperBound = proposalRules_
            .identityCreationTimestampUpperBound -
            IPoseidonSMT(getRegistrationSMT()).ROOT_VALIDITY();
        uint256 identityCounterUpperBound = IDENTITY_LIMIT;

        // If identity is issued after the proposal start, it should not be reissued more than identityCounterUpperBound
        if (userData_.identityCreationTimestamp > 0) {
            identityCreationTimestampUpperBound = userData_.identityCreationTimestamp;
            identityCounterUpperBound = proposalRules_.identityCounterUpperBound;
        }

        uint256 builder_ = PublicSignalsTD1Builder23.newPublicSignalsBuilder(
            proposalRules_.selector,
            userData_.nullifier
        );
        builder_.withCurrentDate(currentDate_, 1 days);
        builder_.withEventIdAndData(
            proposalEventId,
            uint256(uint248(uint256(keccak256(abi.encode(vote_)))))
        );
        builder_.withSex(proposalRules_.sex);
        builder_.withCitizenship(userData_.citizenship);
        // CRITICAL: personalNumber (signal[8]) must match the INID circuit's output
        // The circuit outputs pers_number * selector_bits[1], which is non-zero when bit 16 is set
        builder_.withPersonalNumberHash(userData_.personalNumber);
        builder_.withTimestampLowerboundAndUpperbound(0, identityCreationTimestampUpperBound);
        builder_.withIdentityCounterLowerbound(0, identityCounterUpperBound);
        builder_.withBirthDateLowerboundAndUpperbound(
            proposalRules_.birthDateLowerbound,
            proposalRules_.birthDateUpperbound
        );
        builder_.withExpirationDateLowerboundAndUpperbound(
            proposalRules_.expirationDateLowerBound,
            PublicSignalsTD1Builder23.ZERO_DATE
        );
        
        // CRITICAL: Set citizenshipMask at signal index 22
        // The circuit expects a bitmask where each allowed country has its bit set
        // Bit position = (country_code % 253), e.g., IR (0x4952 = 18770) -> bit 101
        uint256 citizenshipMask_ = _computeCitizenshipMask(proposalRules_.citizenshipWhitelist);
        builder_.withCitizenshipMask(citizenshipMask_);

        return builder_;
    }

    function _buildPublicSignals(
        bytes32,
        uint256,
        bytes memory
    ) internal pure override returns (uint256) {
        revert("TD3 voting is not supported.");
    }

    /**
     * @notice Custom INID voting entry point using 23-signal layout
     * @dev We cannot override executeTD1Noir because it's not virtual in parent.
     *      This function uses our local 23-signal builder which puts idStateRoot 
     *      at index 11 (TD3-style), matching what the INID circuit expects.
     *      
     *      The app should call this function instead of executeTD1Noir!
     */
    function executeINID(
        bytes32 registrationRoot_,
        uint256 currentDate_,
        bytes memory userPayload_,
        bytes memory zkPoints_
    ) external {
        _beforeVerify(registrationRoot_, currentDate_, userPayload_);

        uint256 builder_ = _buildPublicSignalsTD1(registrationRoot_, currentDate_, userPayload_);
        // Use OUR local 23-signal builder's withIdStateRoot (index 11, not 12!)
        builder_.withIdStateRoot(registrationRoot_);

        bytes32[] memory publicSignals_ = PublicSignalsTD1Builder23.buildAsBytesArray(builder_);

        if (!INoirVerifier(getVerifier()).verify(zkPoints_, publicSignals_)) {
            revert InvalidNoirProof23(publicSignals_, zkPoints_);
        }

        _afterVerify(registrationRoot_, currentDate_, userPayload_);
    }

    /**
     * @notice Get public signals for debugging/testing (INID 23-signal layout)
     */
    function getPublicSignalsINID(
        bytes32 registrationRoot_,
        uint256 currentDate_,
        bytes memory userPayload_
    ) public view returns (bytes32[] memory publicSignals) {
        uint256 builder_ = _buildPublicSignalsTD1(registrationRoot_, currentDate_, userPayload_);
        builder_.withIdStateRoot(registrationRoot_);

        return PublicSignalsTD1Builder23.buildAsBytesArray(builder_);
    }
}
