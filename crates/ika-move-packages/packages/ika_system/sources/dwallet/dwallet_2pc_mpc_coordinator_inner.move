// Copyright (c) dWallet Labs Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// This module handles the logic for creating and managing dWallets using the Secp256K1 signature scheme
/// and the DKG process. It leverages validators to execute MPC (Multi-Party Computation)
/// protocols to ensure trustless and decentralized wallet creation and key management.

module ika_system::dwallet_2pc_mpc_coordinator_inner;

use sui::table_vec::{Self, TableVec};
use ika::ika::IKA;
use sui::sui::SUI;
use sui::object_table::{Self, ObjectTable};
use sui::table::{Self, Table};
use sui::balance::{Self, Balance};
use sui::bcs;
use sui::coin::{Coin};
use sui::bag::{Self, Bag};
use sui::event;
use sui::ed25519::ed25519_verify;
use ika_system::address;
use ika_system::bls_committee::{Self, BlsCommittee};
use sui::vec_map::{VecMap};
use sui::event::emit;
use ika_system::dwallet_pricing::{Self, DWalletPricing, DWalletPricingValue, DWalletPricingCalculationVotes};

const CHECKPOINT_MESSAGE_INTENT: vector<u8> = vector[1, 0, 0];

const DKG_FIRST_ROUND_PROTOCOL_FLAG: u32 = 0;
const DKG_SECOND_ROUND_PROTOCOL_FLAG: u32 = 1;
const RE_ENCRYPT_USER_SHARE_PROTOCOL_FLAG: u32 = 2;
const MAKE_DWALLET_USER_SECRET_KEY_SHARE_PUBLIC_PROTOCOL_FLAG: u32 = 3;
const IMPORTED_KEY_DWALLET_VERIFICATION_PROTOCOL_FLAG: u32 = 4;
const PRESIGN_PROTOCOL_FLAG: u32 = 5;
const SIGN_PROTOCOL_FLAG: u32 = 6;
const FUTURE_SIGN_PROTOCOL_FLAG: u32 = 7;
const SIGN_WITH_PARTIAL_USER_SIGNATURE_PROTOCOL_FLAG: u32 = 8;

// Message data type constants corresponding to MessageKind enum variants (in ika-types/src/message.rs)
const DWALLET_DKG_FIRST_ROUND_OUTPUT_MESSAGE_TYPE: u64 = 0;
const DWALLET_DKG_SECOND_ROUND_OUTPUT_MESSAGE_TYPE: u64 = 1;
const DWALLET_ENCRYPTED_USER_SHARE_MESSAGE_TYPE: u64 = 2;
const DWALLET_SIGN_MESSAGE_TYPE: u64 = 3;
const DWALLET_PRESIGN_MESSAGE_TYPE: u64 = 4;
const DWALLET_PARTIAL_SIGNATURE_VERIFICATION_OUTPUT_MESSAGE_TYPE: u64 = 5;
const DWALLET_MPC_NETWORK_DKG_OUTPUT_MESSAGE_TYPE: u64 = 6;
const DWALLET_MPC_NETWORK_RESHARE_OUTPUT_MESSAGE_TYPE: u64 = 7;
const MAKE_DWALLET_USER_SECRET_KEY_SHARES_PUBLIC_MESSAGE_TYPE: u64 = 8;
const DWALLET_IMPORTED_KEY_VERIFICATION_OUTPUT_MESSAGE_TYPE: u64 = 9;
const SET_MAX_ACTIVE_SESSIONS_BUFFER_MESSAGE_TYPE: u64 = 10;

public(package) fun lock_last_active_session_sequence_number(self: &mut DWalletCoordinatorInner) {
    self.locked_last_user_initiated_session_to_complete_in_current_epoch = true;
}

/// A shared object that holds all the Ika system object used to manage dWallets:
///
/// Most importantly, the `dwallets` themselves, which holds the public key and public key shares,
/// and the encryption of the network's share under the network's threshold encryption key.
/// The encryption of the network's secret key share for every dWallet points to an encryption key in `dwallet_network_encryption_keys`,
/// which also stores the encrypted encryption key shares of each validator and their public verification keys.
///
/// For the user side, the secret key share is stored encrypted to the user encryption key (in `encryption_keys`) inside the dWallet,
/// together with a signature on the public key (shares).
/// Together, these constitute the necessary information to create a signature with the user.
///
/// Next, `presign_sessions` holds the outputs of the Presign protocol which are later used for the signing protocol,
/// and `partial_centralized_signed_messages` holds the partial signatures of users awaiting for a future sign once a `MessageApproval` is presented.
///
/// Additionally, this structure holds management information, like the `previous_committee` and `active_committee` committees,
/// information regarding `pricing`, all the `sessions` and the `next_session_sequence_number` that will be used for the next session,
/// and various other fields, like the supported and paused curves, signing algorithms and hashes.
public struct DWalletCoordinatorInner has store {
    current_epoch: u64,
    sessions: ObjectTable<u64, DWalletSession>,
    // Holds events keyed by the ID of the corresponding `DWalletSession` session.
    user_requested_sessions_events: Bag,
    number_of_completed_user_initiated_sessions: u64,
    started_system_sessions_count: u64,
    completed_system_sessions_count: u64,
    /// The sequence number to assign to the next user-requested session.
    /// Initialized to `1` and incremented at every new session creation.
    next_session_sequence_number: u64,
    /// The last MPC session to process in the current epoch.
    /// The validators of the Ika network must always begin sessions,
    /// when they become available to them, so long their sequence number is lesser or equal to this value.
    /// Initialized to `0`, as when the system is initialized no user-requested session exists so none should be started
    /// and we shouldn't wait for any to complete before advancing epoch (until the first session is created),
    /// and updated at every new session creation or completion, and when advancing epochs,
    /// to the latest session whilst assuring a maximum of `max_active_sessions_buffer` sessions to be completed in the current epoch.
    /// Validators should complete every session they start before switching epochs.
    last_user_initiated_session_to_complete_in_current_epoch: u64,
    /// Denotes whether the `last_user_initiated_session_to_complete_in_current_epoch` field is locked or not.
    /// This field gets locked before performing the epoch switch.
    locked_last_user_initiated_session_to_complete_in_current_epoch: bool,
    /// The maximum number of active MPC sessions Ika nodes may run during an epoch.
    /// Validators should complete every session they start before switching epochs.
    max_active_sessions_buffer: u64,
    // TODO: change it to versioned
    /// The key is the ID of `DWallet`.
    dwallets: ObjectTable<ID, DWallet>,
    // TODO: change it to versioned
    /// The key is the ID of `DWalletNetworkEncryptionKey`.
    dwallet_network_encryption_keys: ObjectTable<ID, DWalletNetworkEncryptionKey>,
    // TODO: change it to versioned
    /// A table mapping user addresses to encryption key object IDs.
    encryption_keys: ObjectTable<address, EncryptionKey>,
    /// A table mapping id to their presign sessions.
    presign_sessions: ObjectTable<ID, PresignSession>,
    /// A table mapping id to their partial centralized signed messages.
    partial_centralized_signed_messages: ObjectTable<ID, PartialUserSignature>,
    /// The pricing for the current epoch.
    pricing: DWalletPricing,
    /// The default pricing.
    default_pricing: DWalletPricing,
    /// The votes for the pricing set by validators.
    /// The key is the validator ID to their votes.
    pricing_votes: Table<ID, DWalletPricing>,
    /// The votes for the pricing calculation, if set, we have to complete the pricing
    /// calculation before we advance to the next epoch.
    pricing_calculation_votes: Option<DWalletPricingCalculationVotes>,
    /// Sui gas fee reimbursement to fund the network writing tx responses to sui.
    gas_fee_reimbursement_sui: Balance<SUI>,
    /// The fees paid for consensus validation in IKA.
    consensus_validation_fee_charged_ika: Balance<IKA>,
    /// The active committees.
    active_committee: BlsCommittee,
    /// The previous committee.
    previous_committee: BlsCommittee,
    /// The total messages processed.
    total_messages_processed: u64,
    /// The last checkpoint sequence number processed.
    last_processed_checkpoint_sequence_number: Option<u64>,
    /// The last checkpoint sequence number processed in the previous epoch.
    previous_epoch_last_checkpoint_sequence_number: u64,
    /// A nested map of supported curves to signature algorithms to hash schemes.
    /// e.g. secp256k1 -> [(ecdsa -> [sha256, keccak256]), (schnorr -> [sha256])]
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    /// A list of paused curves in case of emergency.
    /// e.g. [secp256k1, ristretto]
    paused_curves: vector<u32>,
    /// A list of paused signature algorithms in case of emergency.
    /// e.g. [ecdsa, schnorr]
    paused_signature_algorithms: vector<u32>,
    /// A list of paused hash schemes in case of emergency.
    /// e.g. [sha256, keccak256]
    paused_hash_schemes: vector<u32>,
    /// A list of signature algorithms that are allowed for global presign.
    signature_algorithms_allowed_global_presign: vector<u32>,
    /// Any extra fields that's not defined statically.
    extra_fields: Bag,
}

public struct DWalletSessionEventKey has copy, drop, store {}

/// An Ika MPC session.
public struct DWalletSession has key, store {
    id: UID,

    session_sequence_number: u64,

    dwallet_network_encryption_key_id: ID,

    /// The fees paid for consensus validation in IKA.
    consensus_validation_fee_charged_ika: Balance<IKA>,

    /// The fees paid for computation in IKA.
    computation_fee_charged_ika: Balance<IKA>,

    /// Sui gas fee reimbursement to fund the network writing tx responses to sui.
    gas_fee_reimbursement_sui: Balance<SUI>,
}

/// Represents a capability granting control over a specific dWallet.
public struct DWalletCap has key, store {
    id: UID,
    dwallet_id: ID,
}

/// Represents a capability granting control over a specific imported key dWallet.
public struct ImportedKeyDWalletCap has key, store {
    id: UID,
    dwallet_id: ID,
}

/// Represents a capability granting control over a specific dWallet network encryption key.
public struct DWalletNetworkEncryptionKeyCap has key, store {
    id: UID,
    dwallet_network_encryption_key_id: ID,
}

/// `DWalletNetworkEncryptionKey` represents a (threshold) encryption key owned by the network.
/// It stores the `network_dkg_public_output`, which in turn stores the encryption key itself (divided to chunks, due to space limitations).
/// Before the first reconfiguration (which happens at every epoch switch,)
/// `network_dkg_public_output` also holds the encryption of the current encryption key shares
/// (encrypted to each validator's encryption key, and decrypted by them whenever they start)
/// and the public verification keys of all validators, from which the public parameters of the threshold encryption scheme
/// can be generated.
/// After the first reconfiguration, `reconfiguration_public_outputs` holds this information updated for the `current_epoch`.
public struct DWalletNetworkEncryptionKey has key, store {
    id: UID,
    dwallet_network_encryption_key_cap_id: ID,
    current_epoch: u64,
    reconfiguration_public_outputs: sui::table::Table<u64, TableVec<vector<u8>>>,
    network_dkg_public_output: TableVec<vector<u8>>,
    /// The fees paid for computation in IKA.
    computation_fee_charged_ika: Balance<IKA>,
    state: DWalletNetworkEncryptionKeyState,
}

public enum DWalletNetworkEncryptionKeyState has copy, drop, store {
    AwaitingNetworkDKG,
    NetworkDKGCompleted,
    /// Reconfiguration request was sent to the network, but didn't finish yet.
    /// `is_first` is true if this is the first reconfiguration request, false otherwise.
    AwaitingNetworkReconfiguration {
        is_first: bool,
    },
    /// Reconfiguration request finished, but we didn't switch an epoch yet.
    /// We need to wait for the next epoch to update the reconfiguration public outputs.
    AwaitingNextEpochToUpdateReconfiguration,
    NetworkReconfigurationCompleted,
}

/// Represents an encryption key used to encrypt a dWallet centralized (user) secret key share.
///
/// Encryption keys facilitate secure data transfer between accounts on the
/// Ika by ensuring that sensitive information remains confidential during transmission.
///
/// Each address on the Ika is associated with a unique encryption key.
/// When a user intends to send encrypted data (i.e. when sharing the secret key share to grant access and/or transfer a dWallet) to another user,
/// they use the recipient's encryption key to encrypt the data.
/// The recipient is then the sole entity capable of decrypting and accessing this information, ensuring secure, end-to-end encryption.
public struct EncryptionKey has key, store {
    /// Unique identifier for the `EncryptionKey`.
    id: UID,

    created_at_epoch: u64,

    curve: u32,

    //TODO: make sure to include class group type and version inside the bytes with the rust code
    /// Serialized encryption key.
    encryption_key: vector<u8>,

    /// Signature for the encryption key, signed by the `signer_public_key`.
    /// Used to verify the data originated from the `signer_address`.
    encryption_key_signature: vector<u8>,

    /// The public key that was used to sign the `encryption_key`.
    signer_public_key: vector<u8>,

    /// Address of the encryption key owner.
    signer_address: address,
}

/// A verified Encrypted dWallet centralized secret key share.
///
/// This struct represents an encrypted centralized secret key share tied to
/// a specific dWallet (`DWallet`).
/// It includes cryptographic proof that the encryption is valid and securely linked
/// to the associated `dWallet`.
public struct EncryptedUserSecretKeyShare has key, store {
    /// A unique identifier for this encrypted user share object.
    id: UID,

    created_at_epoch: u64,

    /// The ID of the dWallet associated with this encrypted secret share.
    dwallet_id: ID,

    // TODO(@Omer): once we verify the proof, I don't see a need to save it. In fact, I modified the code to not return the proof after verification, just the encryption.
    /// The encrypted centralized secret key share along with a cryptographic proof
    /// that the encryption corresponds to the dWallet's secret key share.
    encrypted_centralized_secret_share_and_proof: vector<u8>,

    /// The ID of the `EncryptionKey` object used to encrypt the secret share.
    encryption_key_id: ID,

    encryption_key_address: address,

    /// The ID of the `EncryptedUserSecretKeyShare` the secret was re-encrypted from (None if created during dkg).
    source_encrypted_user_secret_key_share_id: Option<ID>,

    state: EncryptedUserSecretKeyShareState,
}
public enum EncryptedUserSecretKeyShareState has copy, drop, store {
    AwaitingNetworkVerification,
    NetworkVerificationCompleted,
    NetworkVerificationRejected,
    KeyHolderSigned {
        /// The signed public share corresponding to the encrypted secret key share,
        /// used to verify its authenticity.
        user_output_signature: vector<u8>,
    }
}

public struct UnverifiedPartialUserSignatureCap has key, store {
    /// A unique identifier for this object.
    id: UID,

    /// The unique identifier of the associated PartialCentralizedSignedMessage.
    partial_centralized_signed_message_id: ID,
}

public struct VerifiedPartialUserSignatureCap has key, store {
    /// A unique identifier for this object.
    id: UID,

    /// The unique identifier of the associated PartialCentralizedSignedMessage.
    partial_centralized_signed_message_id: ID,
}

// TODO: add hash_scheme
/// Message that have been signed by a user, a.k.a the centralized party,
/// but not yet by the blockchain.
/// Used for scenarios where the user needs to first agree to sign some transaction,
/// and the blockchain signs this transaction later,
/// when some other conditions are met.
///
/// Can be used to implement an order-book-based exchange, for example.
/// User `A` first agrees to buy BTC with ETH at price X, and signs a transaction with this information.
/// When a matching user `B`, that agrees to sell BTC for ETH at price X,
/// signs a transaction with this information,
/// the blockchain can sign both transactions, and the exchange is completed.
public struct PartialUserSignature has key, store {
    /// A unique identifier for this object.
    id: UID,

    created_at_epoch: u64,

    presign_cap: VerifiedPresignCap,

    dwallet_id: ID,

    cap_id: ID,

    curve: u32,

    signature_algorithm: u32,

    hash_scheme: u32,

    /// The messages that are being signed.
    message: vector<u8>,

    /// The centralized party signature of a message.
    message_centralized_signature: vector<u8>,

    state: PartialUserSignatureState,
}

public enum PartialUserSignatureState has copy, drop, store {
    AwaitingNetworkVerification,
    NetworkVerificationCompleted,
    NetworkVerificationRejected
}

/// `DWallet` represents a decentralized wallet (dWallet) that is
/// created after the Distributed key generation (DKG) process.
public struct DWallet has key, store {
    /// Unique identifier for the dWallet.
    id: UID,

    created_at_epoch: u64,

    /// The elliptic curve used for the dWallet.
    curve: u32,

    /// If not set, the user secret key shares is not public, and the user will need to
    /// keep it encrypted using encrypted user secret key shares. It is
    /// the case where we have zero trust for the dWallet because the
    /// user participation is required.
    /// If set, the user secret key shares is public, the network can sign
    /// without the user participation. In this case, it is trust minimalized
    /// security for the user.
    public_user_secret_key_share: Option<vector<u8>>,

    /// The ID of the capability associated with this dWallet.
    dwallet_cap_id: ID,

    /// The MPC network encryption key id that is used to encrypt this dWallet network secret key share.
    dwallet_network_encryption_key_id: ID,

    /// Key was imported.
    is_imported_key_dwallet: bool,

    /// A table mapping id to their encryption key object.
    encrypted_user_secret_key_shares: ObjectTable<ID, EncryptedUserSecretKeyShare>,

    sign_sessions: ObjectTable<ID, SignSession>,

    state: DWalletState,
}

public enum DWalletState has copy, drop, store {
    // DKG
    DKGRequested,
    NetworkRejectedDKGRequest,
    AwaitingUserDKGVerificationInitiation {
        first_round_output: vector<u8>,
    },
    AwaitingNetworkDKGVerification,
    NetworkRejectedDKGVerification,

    // Imported Key
    AwaitingUserImportedKeyInitiation,
    AwaitingNetworkImportedKeyVerification,
    NetworkRejectedImportedKeyVerification,

    AwaitingKeyHolderSignature {
        public_output: vector<u8>,
    },

    // Active for both DKG and Imported Key
    Active {
        /// The output of the DKG process.
        public_output: vector<u8>,
    }
}

public struct UnverifiedPresignCap has key, store {
    id: UID,

    /// The ID of the dWallet for which this Presign has been created and can be used by exclusively, if set.
    /// Optional, since some key signature algorithms (e.g., Schnorr and EdDSA) can support global presigns,
    /// which can be used for any dWallet (under the same network key). Others, like ECDSA, must have this set.
    dwallet_id: Option<ID>,

    /// The ID of the presign.
    presign_id: ID,
}

public struct VerifiedPresignCap has key, store {
    id: UID,

    /// The ID of the dWallet for which this Presign has been created and can be used by exclusively, if set.
    /// Optional, since some key signature algorithms (e.g., Schnorr and EdDSA) can support global presigns,
    /// which can be used for any dWallet (under the same network key). Others, like ECDSA, must have this set.
    dwallet_id: Option<ID>,

    /// The ID of the presign.
    presign_id: ID,
}

/// A session of the Presign protocol.
/// When `state` is `PresignState::Completed`, holds a presign:
/// a single-use precomputation that does not depend on the message,
/// used to speed up the (online) Sign protocol.
public struct PresignSession has key, store {
    /// Unique identifier for the presign object.
    id: UID,

    created_at_epoch: u64,

    /// The elliptic curve used for the dWallet.
    curve: u32,

    /// The signature algorithm for the presign.
    signature_algorithm: u32,

    /// The ID of the dWallet for which this Presign has been created and can be used by exclusively, if set.
    /// Optional, since some key signature algorithms (e.g., Schnorr and EdDSA) can support global presigns,
    /// which can be used for any dWallet (under the same network key).
    dwallet_id: Option<ID>,

    cap_id: ID,

    state: PresignState,
}

public enum PresignState has copy, drop, store {
    Requested,
    NetworkRejected,
    Completed {
        presign: vector<u8>,
    }
}

/// A Sign session. When `state` is `SignState::Completed`, holds the `signature`.
public struct SignSession has key, store {
    id: UID,

    created_at_epoch: u64,

    /// The unique identifier of the associated dWallet.
    dwallet_id: ID,

    /// The session identifier for the sign process.
    session_id: ID,

    state: SignState,
}

public enum SignState has copy, drop, store {
    Requested,
    NetworkRejected,
    Completed {
        signature: vector<u8>,
    }
}

/// The dWallet MPC session type
/// User initiated sessions have a sequence number, which is used to determine in which epoch
/// the session will get completed.
/// System sessions are guaranteed to always get completed in the epoch they were created in.
public enum SessionType has copy, drop, store {
    User {
        sequence_number: u64,
    },
    System
}

public struct DWalletEvent<E: copy + drop + store> has copy, drop, store {
    epoch: u64,
    session_type: SessionType,
    session_id: ID,
    event_data: E,
}

/// Event emitted when an encryption key is created.
///
/// This event is emitted after the blockchain verifies the encryption key's validity
/// and creates the corresponding `EncryptionKey` object.
public struct CreatedEncryptionKeyEvent has copy, drop, store {
    /// The unique identifier of the created `EncryptionKey` object.
    encryption_key_id: ID,

    signer_address: address,
}

public struct DWalletNetworkDKGEncryptionKeyRequestEvent has copy, drop, store {
    dwallet_network_encryption_key_id: ID,
}


/// An event emitted when the first round of the DKG process is completed.
///
/// This event is emitted by the blockchain to notify the user about
/// the completion of the first round.
/// The user should catch this event to generate inputs for
/// the second round and call the `request_dwallet_dkg_second_round()` function.
public struct CompletedDWalletNetworkDKGEncryptionKeyEvent has copy, drop, store {
    dwallet_network_encryption_key_id: ID,
}

public struct RejectedDWalletNetworkDKGEncryptionKeyEvent has copy, drop, store {
    dwallet_network_encryption_key_id: ID,
}

public struct DWalletEncryptionKeyReconfigurationRequestEvent has copy, drop, store {
    dwallet_network_encryption_key_id: ID,
}

public struct CompletedDWalletEncryptionKeyReconfigurationEvent has copy, drop, store {
    dwallet_network_encryption_key_id: ID,
}

public struct RejectedDWalletEncryptionKeyReconfigurationEvent has copy, drop, store {
    dwallet_network_encryption_key_id: ID,
}

// DKG TYPES

/// Event emitted to start the first round of the DKG process.
///
/// This event is caught by the blockchain, which is then using it to
/// initiate the first round of the DKG.
public struct DWalletDKGFirstRoundRequestEvent has copy, drop, store {
    /// The unique session identifier for the DKG process.
    dwallet_id: ID,

    /// The identifier for the dWallet capability.
    dwallet_cap_id: ID,

    /// The MPC network encryption key id that is used to encrypt associated dWallet network secret key share.
    dwallet_network_encryption_key_id: ID,

    /// The elliptic curve used for the dWallet.
    curve: u32,
}

/// An event emitted when the first round of the DKG process is completed.
///
/// This event is emitted by the blockchain to notify the user about
/// the completion of the first round.
/// The user should catch this event to generate inputs for
/// the second round and call the `request_dwallet_dkg_second_round()` function.
public struct CompletedDWalletDKGFirstRoundEvent has copy, drop, store {
    /// The unique session identifier for the DKG process.
    dwallet_id: ID,

    /// The decentralized public output data produced by the first round of the DKG process.
    first_round_output: vector<u8>,
}

public struct RejectedDWalletDKGFirstRoundEvent has copy, drop, store {
    dwallet_id: ID,
}

/// Event emitted to initiate the second round of the DKG process.
///
/// This event is emitted to notify Validators to begin the second round of the DKG.
/// It contains all necessary data to ensure proper continuation of the process.
public struct DWalletDKGSecondRoundRequestEvent has copy, drop, store {
    encrypted_user_secret_key_share_id: ID,
    /// The unique session identifier for the DWallet.
    dwallet_id: ID,

    /// The output from the first round of the DKG process.
    first_round_output: vector<u8>,

    /// A serialized vector containing the centralized public key share and its proof.
    centralized_public_key_share_and_proof: vector<u8>,

    /// The unique identifier of the dWallet capability associated with this session.
    dwallet_cap_id: ID,

    /// Encrypted centralized secret key share and the associated cryptographic proof of encryption.
    encrypted_centralized_secret_share_and_proof: vector<u8>,

    /// The `EncryptionKey` object used for encrypting the secret key share.
    encryption_key: vector<u8>,

    /// The unique identifier of the `EncryptionKey` object.
    encryption_key_id: ID,

    encryption_key_address: address,

    /// The public output of the centralized party in the DKG process.
    user_public_output: vector<u8>,

    /// The Ed25519 public key of the initiator,
    /// used to verify the signature on the centralized public output.
    signer_public_key: vector<u8>,

    /// The MPC network encryption key id that is used to encrypt associated dWallet network secret key share.
    dwallet_network_encryption_key_id: ID,

    /// The elliptic curve used for the dWallet.
    curve: u32,
}

/// Event emitted upon the completion of the second (and final) round of the
/// Distributed Key Generation (DKG).
///
/// This event provides all necessary data generated from the second
/// round of the DKG process.
/// Emitted to notify the centralized party.
public struct CompletedDWalletDKGSecondRoundEvent has copy, drop, store {
    /// The identifier of the dWallet created as a result of the DKG process.
    dwallet_id: ID,

    /// The public output for the second round of the DKG process.
    public_output: vector<u8>,
    encrypted_user_secret_key_share_id: ID,
    session_id: ID
}

public struct RejectedDWalletDKGSecondRoundEvent has copy, drop, store {
    /// The identifier of the dWallet created as a result of the DKG process.
    dwallet_id: ID,

    /// The public output for the second round of the DKG process.
    public_output: vector<u8>,
}

// END OF DKG TYPES


public struct DWalletImportedKeyVerificationRequestEvent has copy, drop, store {
    /// The unique session identifier for the DWallet.
    dwallet_id: ID,

    encrypted_user_secret_key_share_id: ID,

    centralized_party_message: vector<u8>,

    /// The unique identifier of the dWallet capability associated with this session.
    dwallet_cap_id: ID,

    /// Encrypted centralized secret key share and the associated cryptographic proof of encryption.
    encrypted_centralized_secret_share_and_proof: vector<u8>,

    /// The `EncryptionKey` object used for encrypting the secret key share.
    encryption_key: vector<u8>,

    /// The unique identifier of the `EncryptionKey` object.
    encryption_key_id: ID,

    encryption_key_address: address,

    /// The public output of the centralized party in the DKG process.
    user_public_output: vector<u8>,

    /// The Ed25519 public key of the initiator,
    /// used to verify the signature on the centralized public output.
    signer_public_key: vector<u8>,

    /// The MPC network encryption key id that is used to encrypt associated dWallet network secret key share.
    dwallet_network_encryption_key_id: ID,

    /// The elliptic curve used for the dWallet.
    curve: u32,
}

public struct CompletedDWalletImportedKeyVerificationEvent has copy, drop, store {
    dwallet_id: ID,

    public_output: vector<u8>,
    encrypted_user_secret_key_share_id: ID,
    session_id: ID
}

public struct RejectedDWalletImportedKeyVerificationEvent has copy, drop, store {
    dwallet_id: ID,
}


// ENCRYPTED USER SHARE TYPES

/// Event emitted to start an encrypted dWallet centralized (user) key share
/// verification process.
/// Ika does not support native functions, so an event is emitted and
/// caught by the blockchain, which then starts the verification process,
/// similar to the MPC processes.
public struct EncryptedShareVerificationRequestEvent has copy, drop, store {
    /// Encrypted centralized secret key share and the associated cryptographic proof of encryption.
    encrypted_centralized_secret_share_and_proof: vector<u8>,

    /// The public output of the centralized party,
    /// belongs to the dWallet that its centralized
    /// secret share is being encrypted.
    /// This is not passed by the user,
    /// but taken from the blockchain during event creation.
    public_output: vector<u8>,

    /// The ID of the dWallet that this encrypted secret key share belongs to.
    dwallet_id: ID,

    /// The encryption key used to encrypt the secret key share with.
    encryption_key: vector<u8>,

    /// The `EncryptionKey` Move object ID.
    encryption_key_id: ID,

    encrypted_user_secret_key_share_id: ID,

    source_encrypted_user_secret_key_share_id: ID,
    dwallet_network_encryption_key_id: ID,

    curve: u32,
}

public struct CompletedEncryptedShareVerificationEvent has copy, drop, store {
    /// The ID of the `EncryptedUserSecretKeyShare` Move object.
    encrypted_user_secret_key_share_id: ID,

    /// The ID of the dWallet associated with this encrypted secret share.
    dwallet_id: ID,
}

public struct RejectedEncryptedShareVerificationEvent has copy, drop, store {
    /// The ID of the `EncryptedUserSecretKeyShare` Move object.
    encrypted_user_secret_key_share_id: ID,

    /// The ID of the dWallet associated with this encrypted secret share.
    dwallet_id: ID,
}

public struct AcceptEncryptedUserShareEvent has copy, drop, store {
    /// The ID of the `EncryptedUserSecretKeyShare` Move object.
    encrypted_user_secret_key_share_id: ID,

    /// The ID of the dWallet associated with this encrypted secret share.
    dwallet_id: ID,

    user_output_signature: vector<u8>,

    encryption_key_id: ID,

    encryption_key_address: address,
}
// END OF ENCRYPTED USER SHARE TYPES


public struct MakeDWalletUserSecretKeySharePublicRequestEvent has copy, drop, store {
    public_user_secret_key_share: vector<u8>,

    public_output: vector<u8>,

    curve: u32,

    dwallet_id: ID,

    dwallet_network_encryption_key_id: ID,
}

public struct CompletedMakeDWalletUserSecretKeySharePublicEvent has copy, drop, store {
    dwallet_id: ID,
}

public struct RejectedMakeDWalletUserSecretKeySharePublicEvent has copy, drop, store {
    dwallet_id: ID,
}

// PRESIGN TYPES

/// Event emitted to initiate the first round of a Presign session.
///
/// This event is used to signal Validators to start the
/// first round of the Presign process.
/// The event includes all necessary details to link
/// the session to the corresponding dWallet
/// and DKG process.
public struct PresignRequestEvent has copy, drop, store {
    /// The ID of the dWallet for which this Presign has been created and can be used by exclusively, if set.
    /// Optional, since some key signature algorithms (e.g., Schnorr and EdDSA) can support global presigns,
    /// which can be used for any dWallet (under the same network key).
    dwallet_id: Option<ID>,

    /// The ID of the presign.
    presign_id: ID,

    /// The output produced by the DKG process,
    /// used as input for the Presign session.
    dwallet_public_output: Option<vector<u8>>,

    /// The MPC network encryption key id that is used to encrypt associated dWallet network secret key share.
    dwallet_network_encryption_key_id: ID,

    /// The curve used for the presign.
    curve: u32,

    /// The signature algorithm for the presign.
    signature_algorithm: u32,
}

/// Event emitted when the presign batch is completed.
///
/// This event indicates the successful completion of a batched presign process.
/// It provides details about the presign objects created and their associated metadata.
public struct CompletedPresignEvent has copy, drop, store {
    /// The ID of the dWallet for which this Presign has been created and can be used by exclusively, if set.
    /// Optional, since some key signature algorithms (e.g., Schnorr and EdDSA) can support global presigns,
    /// which can be used for any dWallet (under the same network key).
    dwallet_id: Option<ID>,

    /// The session ID.
    session_id: ID,
    presign_id: ID,
    presign: vector<u8>,
}

public struct RejectedPresignEvent has copy, drop, store {
    /// The ID of the dWallet for which this Presign has been created and can be used by exclusively, if set.
    /// Optional, since some key signature algorithms (e.g., Schnorr and EdDSA) can support global presigns,
    /// which can be used for any dWallet (under the same network key).
    dwallet_id: Option<ID>,

    /// The session ID.
    session_id: ID,
    presign_id: ID
}

// END OF PRESIGN TYPES


/// Event emitted to initiate the signing process.
///
/// This event is captured by Validators to start the signing protocol.
/// It includes all the necessary information to link the signing process
/// to a specific dWallet, and batched process.
/// D: The type of data that can be stored with the object,
/// specific to each Digital Signature Algorithm.
public struct SignRequestEvent has copy, drop, store {
    sign_id: ID,

    /// The unique identifier for the dWallet used in the session.
    dwallet_id: ID,

    /// The output from the dWallet DKG process used in this session.
    dwallet_public_output: vector<u8>,

    /// The elliptic curve used for the dWallet.
    curve: u32,

    /// The signature algorithm used for the signing process.
    signature_algorithm: u32,

    hash_scheme: u32,

    /// The message to be signed in this session.
    message: vector<u8>,

    /// The MPC network encryption key id that is used to encrypt associated dWallet network secret key share.
    dwallet_network_encryption_key_id: ID,

    /// The presign object ID, this ID will
    /// be used as the signature MPC protocol ID.
    presign_id: ID,

    /// The presign protocol output as bytes.
    presign: vector<u8>,

    /// The centralized party signature of a message.
    message_centralized_signature: vector<u8>,

    /// Indicates whether the future sign feature was used to start the session.
    is_future_sign: bool,
}

/// Event emitted when a [`PartialCentralizedSignedMessages`] object is created.
public struct FutureSignRequestEvent has copy, drop, store {
    dwallet_id: ID,
    partial_centralized_signed_message_id: ID,
    message: vector<u8>,
    presign: vector<u8>,
    dwallet_public_output: vector<u8>,
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
    message_centralized_signature: vector<u8>,
    dwallet_network_encryption_key_id: ID,
}

public struct CompletedFutureSignEvent has copy, drop, store {
    session_id: ID,
    dwallet_id: ID,
    partial_centralized_signed_message_id: ID,
}

public struct RejectedFutureSignEvent has copy, drop, store {
    session_id: ID,
    dwallet_id: ID,
    partial_centralized_signed_message_id: ID,
}

/// Event emitted to signal the completion of a Sign process.
///
/// This event contains signatures for all signed messages in the batch.
public struct CompletedSignEvent has copy, drop, store {
    sign_id: ID,

    /// The session identifier for the signing process.
    session_id: ID,

    /// The signature that was generated in this session.
    signature: vector<u8>,

    /// Indicates whether the future sign feature was used to start the session.
    is_future_sign: bool,
}

public struct RejectedSignEvent has copy, drop, store {
    sign_id: ID,

    /// The session identifier for the signing process.
    session_id: ID,

    /// Indicates whether the future sign feature was used to start the session.
    is_future_sign: bool,
}

/// Event containing dwallet 2pc-mpc checkpoint information, emitted during
/// the checkpoint submission message.
public struct DWalletCheckpointInfoEvent has copy, drop, store {
    epoch: u64,
    sequence_number: u64,
    timestamp_ms: u64,
}

// <<<<<<<<<<<<<<<<<<<<<<<< Error codes <<<<<<<<<<<<<<<<<<<<<<<<
const EDWalletMismatch: u64 = 1;
const EDWalletInactive: u64 = 2;
const EDWalletNotExists: u64 = 3;
const EWrongState: u64 = 4;
const EDWalletNetworkEncryptionKeyNotExist: u64 = 5;
const EInvalidEncryptionKeySignature: u64 = 6;
const EMessageApprovalMismatch: u64 = 7;
const EInvalidHashScheme: u64 = 8;
const ESignWrongState: u64 = 9;
const EPresignNotExist: u64 = 10;
const EIncorrectCap: u64 = 11;
const EUnverifiedCap: u64 = 12;
const EInvalidSource: u64 =13;
const EDWalletNetworkEncryptionKeyNotActive: u64 = 14;
const EInvalidPresign: u64 = 15;
const ECannotAdvanceEpoch: u64 = 16;
const EInvalidCurve: u64 = 17;
const EInvalidSignatureAlgorithm: u64 = 18;
const ECurvePaused: u64 = 19;
const ESignatureAlgorithmPaused: u64 = 20;
const EDWalletUserSecretKeySharesAlreadyPublic: u64 = 21;
const EMismatchCurve: u64 = 22;
const EImportedKeyDWallet: u64 = 23;
const ENotImportedKeyDWallet: u64 = 24;
const EHashSchemePaused: u64 = 25;
const EEncryptionKeyNotExist: u64 = 26;
const EMissingProtocolPricing: u64 = 27;
const EPricingCalculationVotesHasNotBeenStarted: u64 = 28;
const EPricingCalculationVotesMustBeCompleted: u64 = 29;
const ECannotSetDuringVotesCalculation: u64 = 30;

#[error]
const EIncorrectEpochInCheckpoint: vector<u8> = b"The checkpoint epoch is incorrect.";

#[error]
const EWrongCheckpointSequenceNumber: vector<u8> = b"The checkpoint sequence number should be the expected next one.";

#[error]
const EActiveBlsCommitteeMustInitialize: vector<u8> = b"First active committee must initialize.";

// >>>>>>>>>>>>>>>>>>>>>>>> Error codes >>>>>>>>>>>>>>>>>>>>>>>>

public(package) fun create_dwallet_coordinator_inner(
    current_epoch: u64,
    active_committee: BlsCommittee,
    pricing: DWalletPricing,
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    ctx: &mut TxContext
): DWalletCoordinatorInner {
    verify_pricing_exists_for_all_protocols(&supported_curves_to_signature_algorithms_to_hash_schemes, &pricing);
    DWalletCoordinatorInner {
        current_epoch,
        sessions: object_table::new(ctx),
        user_requested_sessions_events: bag::new(ctx),
        number_of_completed_user_initiated_sessions: 0,
        next_session_sequence_number: 1,
        last_user_initiated_session_to_complete_in_current_epoch: 0,
        // TODO (#856): Allow configuring the max_active_session_buffer field
        max_active_sessions_buffer: 100,
        locked_last_user_initiated_session_to_complete_in_current_epoch: true,
        dwallets: object_table::new(ctx),
        dwallet_network_encryption_keys: object_table::new(ctx),
        encryption_keys: object_table::new(ctx),
        presign_sessions: object_table::new(ctx),
        partial_centralized_signed_messages: object_table::new(ctx),
        pricing,
        default_pricing: pricing,
        pricing_votes: table::new(ctx),
        pricing_calculation_votes: option::none(),
        gas_fee_reimbursement_sui: balance::zero(),
        consensus_validation_fee_charged_ika: balance::zero(),
        active_committee,
        previous_committee: bls_committee::empty(),
        total_messages_processed: 0,
        last_processed_checkpoint_sequence_number: option::none(),
        completed_system_sessions_count: 0,
        started_system_sessions_count: 0,
        previous_epoch_last_checkpoint_sequence_number: 0,
        supported_curves_to_signature_algorithms_to_hash_schemes,
        paused_curves: vector[],
        paused_signature_algorithms: vector[],
        paused_hash_schemes: vector[],
        signature_algorithms_allowed_global_presign: vector[],
        extra_fields: bag::new(ctx),
    }
}

/// Start a Distributed Key Generation (DKG) session for the network (threshold) encryption key.
public(package) fun request_dwallet_network_encryption_key_dkg(
    self: &mut DWalletCoordinatorInner,
    ctx: &mut TxContext
): DWalletNetworkEncryptionKeyCap {
    // Create a new capability to control this encryption key.
    let id = object::new(ctx);
    let dwallet_network_encryption_key_id = id.to_inner();
    let cap = DWalletNetworkEncryptionKeyCap {
        id: object::new(ctx),
        dwallet_network_encryption_key_id,
    };

    // Create a new network encryption key and add it to the shared state.
    self.dwallet_network_encryption_keys.add(dwallet_network_encryption_key_id, DWalletNetworkEncryptionKey {
        id,
        dwallet_network_encryption_key_cap_id: object::id(&cap),
        current_epoch: self.current_epoch,
        reconfiguration_public_outputs: sui::table::new(ctx),
        network_dkg_public_output: table_vec::empty(ctx),
        computation_fee_charged_ika: balance::zero(),
        state: DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG,
    });

    // Emit an event to initiate the session in the Ika network.
    event::emit(self.create_system_dwallet_event(
        DWalletNetworkDKGEncryptionKeyRequestEvent {
            dwallet_network_encryption_key_id
        },
        ctx,
    ));

    // Return the capability.
    cap
}

/// Complete the Distributed Key Generation (DKG) session
/// and store the public output corresponding to the newly created network (threshold) encryption key.
///
/// Note: assumes the public output is divided into chunks and each `network_public_output_chunk` is delivered in order,
/// with `is_last_chunk` set for the last call.
public(package) fun respond_dwallet_network_encryption_key_dkg(
    self: &mut DWalletCoordinatorInner,
    dwallet_network_encryption_key_id: ID,
    network_public_output_chunk: vector<u8>,
    is_last_chunk: bool,
    rejected: bool,
    ctx: &mut TxContext,
) {
    if (is_last_chunk) {
        self.completed_system_sessions_count = self.completed_system_sessions_count + 1;
    };
    let dwallet_network_encryption_key = self.dwallet_network_encryption_keys.borrow_mut(
        dwallet_network_encryption_key_id
    );
    if (rejected) {
        dwallet_network_encryption_key.state = DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG;
        // TODO(@scaly): should we empty dwallet_network_encryption_key.network_dkg_public_output?
        emit(RejectedDWalletNetworkDKGEncryptionKeyEvent {
            dwallet_network_encryption_key_id,
        });
        event::emit(self.create_system_dwallet_event(
            DWalletNetworkDKGEncryptionKeyRequestEvent {
                dwallet_network_encryption_key_id,
            },
            ctx,
        ));
    } else {
        dwallet_network_encryption_key.network_dkg_public_output.push_back(network_public_output_chunk);
        dwallet_network_encryption_key.state = match (&dwallet_network_encryption_key.state) {
            DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG => {
            if (is_last_chunk) {
                event::emit(CompletedDWalletNetworkDKGEncryptionKeyEvent {
                    dwallet_network_encryption_key_id,
                });
                DWalletNetworkEncryptionKeyState::NetworkDKGCompleted
            } else {
                DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
            }
        },
            _ => abort EWrongState
        };
    }
}

/// Complete the Reconfiguration session
/// and store the public output corresponding to the reconfigured network (threshold) encryption key.
///
/// Note: assumes the public output is divided into chunks and each `network_public_output_chunk` is delivered in order,
/// with `is_last_chunk` set for the last call.
public(package) fun respond_dwallet_network_encryption_key_reconfiguration(
    self: &mut DWalletCoordinatorInner,
    dwallet_network_encryption_key_id: ID,
    public_output: vector<u8>,
    is_last_chunk: bool,
    rejected: bool,
    ctx: &mut TxContext,
) {
    // The Reconfiguration output can be large, so it is seperated into chunks.
    // We should only update the count once, so we check it is the last chunk before we do.
    if (is_last_chunk) {
        self.completed_system_sessions_count = self.completed_system_sessions_count + 1;
    };

    // Store this chunk as the last chunk in the chunks vector corresponding to the upcoming's epoch in the public outputs map.
    let dwallet_network_encryption_key = self.dwallet_network_encryption_keys.borrow_mut(dwallet_network_encryption_key_id);
    if (rejected) {
        dwallet_network_encryption_key.state = match (&dwallet_network_encryption_key.state) {
            DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first } => {
                DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first: *is_first }
            },
            _ => DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first: false }
        };
        // TODO(@scaly): should we empty next_reconfiguration_public_output?
        emit(RejectedDWalletEncryptionKeyReconfigurationEvent {
            dwallet_network_encryption_key_id,
        });
        event::emit(self.create_system_dwallet_event(
            DWalletEncryptionKeyReconfigurationRequestEvent {
                dwallet_network_encryption_key_id,
            },
            ctx,
        ));
    } else {

    let next_reconfiguration_public_output = dwallet_network_encryption_key.reconfiguration_public_outputs.borrow_mut(dwallet_network_encryption_key.current_epoch + 1);
    // Change state to complete and emit an event to signify that only if it is the last chunk.
    next_reconfiguration_public_output.push_back(public_output);
    dwallet_network_encryption_key.state = match (&dwallet_network_encryption_key.state) {
        DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first } => {
            if (is_last_chunk) {
                    event::emit(CompletedDWalletEncryptionKeyReconfigurationEvent {
                        dwallet_network_encryption_key_id,
                    });
                    DWalletNetworkEncryptionKeyState::AwaitingNextEpochToUpdateReconfiguration
                } else {
                    DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first: *is_first }
                }
            },
        _ => abort EWrongState
    };
    }
}

/// Advance the `current_epoch` and `state` of the network encryption key corresponding to `cap`,
/// finalizing the reconfiguration of that key, and readying it for use in the next epoch.
fun advance_epoch_dwallet_network_encryption_key(
    self: &mut DWalletCoordinatorInner,
    cap: &DWalletNetworkEncryptionKeyCap,
): Balance<IKA> {
    // Get the corresponding network encryption key.
    let dwallet_network_encryption_key = self.get_active_dwallet_network_encryption_key(
        cap.dwallet_network_encryption_key_id
    );

    // Sanity checks: check the capability is the right one, and that the key is in the right state.
    assert!(dwallet_network_encryption_key.dwallet_network_encryption_key_cap_id == cap.id.to_inner(), EIncorrectCap);
    assert!(dwallet_network_encryption_key.state == DWalletNetworkEncryptionKeyState::AwaitingNextEpochToUpdateReconfiguration, EWrongState);

    // Advance the current epoch and state.
    dwallet_network_encryption_key.current_epoch = dwallet_network_encryption_key.current_epoch + 1;
    dwallet_network_encryption_key.state = DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted;

    // Return the fees.
    let mut epoch_computation_fee_charged_ika = sui::balance::zero<IKA>();
    epoch_computation_fee_charged_ika.join(dwallet_network_encryption_key.computation_fee_charged_ika.withdraw_all());
    return epoch_computation_fee_charged_ika
}

public(package) fun mid_epoch_reconfiguration(
    self: &mut DWalletCoordinatorInner,
    next_epoch_active_committee: BlsCommittee,
    dwallet_network_encryption_key_caps: &vector<DWalletNetworkEncryptionKeyCap>,
    ctx: &mut TxContext,
) {
    let pricing_calculation_votes = dwallet_pricing::new_pricing_calculation(next_epoch_active_committee, self.default_pricing);
    self.pricing_calculation_votes = option::some(pricing_calculation_votes);
    dwallet_network_encryption_key_caps.do_ref!(|cap| self.emit_start_reconfiguration_event(cap, ctx));
}

public(package) fun calculate_pricing_votes(
    self: &mut DWalletCoordinatorInner,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
) {
    assert!(self.pricing_calculation_votes.is_some(), EPricingCalculationVotesHasNotBeenStarted);
    let pricing_calculation_votes = self.pricing_calculation_votes.borrow_mut();
    let pricing_votes = pricing_calculation_votes.committee_members_for_pricing_calculation_votes().map!(|id| {
        if (self.pricing_votes.contains(id)) {
            self.pricing_votes[id]
        } else {
            self.default_pricing
        }
    });
    pricing_calculation_votes.calculate_pricing_quorum_below(pricing_votes, curve, signature_algorithm, protocol);
    if(pricing_calculation_votes.is_calculation_completed()) {
        self.pricing = pricing_calculation_votes.calculated_pricing();
        self.pricing_calculation_votes = option::none();
    }
}

/// Emit an event to the Ika network to request a reconfiguration session for the network encryption key corresponding to `cap`.
fun emit_start_reconfiguration_event(
    self: &mut DWalletCoordinatorInner, cap: &DWalletNetworkEncryptionKeyCap, ctx: &mut TxContext
) {
    assert!(self.dwallet_network_encryption_keys.contains(cap.dwallet_network_encryption_key_id), EDWalletNetworkEncryptionKeyNotExist);

    let dwallet_network_encryption_key = self.get_active_dwallet_network_encryption_key(cap.dwallet_network_encryption_key_id);

    dwallet_network_encryption_key.state = match (&dwallet_network_encryption_key.state) {
        DWalletNetworkEncryptionKeyState::NetworkDKGCompleted => {
            DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first: true }
        },
        DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted => {
            DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration { is_first: false }
        },
        _ => return, // TODO(@scaly): should not happen, what do you think?
    };

    // Initialize the chunks vector corresponding to the upcoming's epoch in the public outputs map.
    dwallet_network_encryption_key.reconfiguration_public_outputs.add(dwallet_network_encryption_key.current_epoch + 1, table_vec::empty(ctx));

    // Emit the event to the Ika network, requesting they start the reconfiguration session.
    event::emit(self.create_system_dwallet_event(
        DWalletEncryptionKeyReconfigurationRequestEvent {
            dwallet_network_encryption_key_id: cap.dwallet_network_encryption_key_id
        },
        ctx,
    ));
}

fun get_active_dwallet_network_encryption_key(
    self: &mut DWalletCoordinatorInner,
    dwallet_network_encryption_key_id: ID,
): &mut DWalletNetworkEncryptionKey {
    let dwallet_network_encryption_key = self.dwallet_network_encryption_keys.borrow_mut(dwallet_network_encryption_key_id);

    assert!(dwallet_network_encryption_key.state != DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG, EDWalletNetworkEncryptionKeyNotActive);

    dwallet_network_encryption_key
}

/// Advance the epoch.
///
/// Checks that all the current epoch sessions are completed,
/// and updates the required metadata for the next epoch's sessions management.
///
/// Sets the current and previous committees.
///
/// Unlocks and updates `last_user_initiated_session_to_complete_in_current_epoch`.
///
/// And finally increments the `current_epoch`.
public(package) fun advance_epoch(
    self: &mut DWalletCoordinatorInner,
    next_committee: BlsCommittee,
    dwallet_network_encryption_key_caps: &vector<DWalletNetworkEncryptionKeyCap>,
): Balance<IKA> {
    assert!(self.pricing_calculation_votes.is_none(), EPricingCalculationVotesMustBeCompleted);
    // assert!(self.all_current_epoch_user_initiated_sessions_completed(), ECannotAdvanceEpoch);

    if (self.last_processed_checkpoint_sequence_number.is_some()) {
        let last_processed_checkpoint_sequence_number = *self.last_processed_checkpoint_sequence_number.borrow();
        self.previous_epoch_last_checkpoint_sequence_number = last_processed_checkpoint_sequence_number;
    };

    self.locked_last_user_initiated_session_to_complete_in_current_epoch = false;
    self.update_last_user_initiated_session_to_complete_in_current_epoch();

    self.current_epoch = self.current_epoch + 1;

    self.previous_committee = self.active_committee;
    self.active_committee = next_committee;

    let mut balance = balance::zero<IKA>();
    dwallet_network_encryption_key_caps.do_ref!(|cap| {
        balance.join(self.advance_epoch_dwallet_network_encryption_key(cap));
    });
    balance.join(self.consensus_validation_fee_charged_ika.withdraw_all());
    balance
}

fun get_dwallet(
    self: &DWalletCoordinatorInner,
    dwallet_id: ID,
): &DWallet {
    assert!(self.dwallets.contains(dwallet_id), EDWalletNotExists);

    self.dwallets.borrow(dwallet_id)
}

fun get_dwallet_mut(
    self: &mut DWalletCoordinatorInner,
    dwallet_id: ID,
): &mut DWallet {
    assert!(self.dwallets.contains(dwallet_id), EDWalletNotExists);

    self.dwallets.borrow_mut(dwallet_id)
}

fun validate_active_and_get_public_output(
    self: &DWallet,
): &vector<u8> {
    match (&self.state) {
        DWalletState::Active {
            public_output,
        } => {
            public_output
        },
        DWalletState::DKGRequested |
        DWalletState::NetworkRejectedDKGRequest |
        DWalletState::AwaitingUserDKGVerificationInitiation { .. } |
        DWalletState::AwaitingNetworkDKGVerification |
        DWalletState::NetworkRejectedDKGVerification |
        DWalletState::AwaitingUserImportedKeyInitiation |
        DWalletState::AwaitingNetworkImportedKeyVerification |
        DWalletState::NetworkRejectedImportedKeyVerification |
        DWalletState::AwaitingKeyHolderSignature { .. } => abort EDWalletInactive,
    }
}

/// Creates a new MPC session and charges the user for it.
///
/// Payment is done in both Ika (for the MPC computation by the Ika network)
/// and Sui (for storing the public output in Sui).
/// The payment is saved in the session object, for it is to be distributed only upon the completion of the session.
///
/// The newly created session has its sequence number set to `next_session_sequence_number`, which is then incremented.
/// Finally, the last session to complete in current epoch is updated, if needed.
fun charge_and_create_current_epoch_dwallet_event<E: copy + drop + store>(
    self: &mut DWalletCoordinatorInner,
    dwallet_network_encryption_key_id: ID,
    pricing_value: DWalletPricingValue,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    event_data: E,
    ctx: &mut TxContext,
): DWalletEvent<E> {
    assert!(self.dwallet_network_encryption_keys.contains(dwallet_network_encryption_key_id), EDWalletNetworkEncryptionKeyNotExist);

    let computation_fee_charged_ika = payment_ika.split(pricing_value.computation_ika(), ctx).into_balance();

    let consensus_validation_fee_charged_ika = payment_ika.split(pricing_value.consensus_validation_ika(), ctx).into_balance();
    let mut gas_fee_reimbursement_sui = payment_sui.split(pricing_value.gas_fee_reimbursement_sui(), ctx).into_balance();
    let gas_fee_reimbursement_sui_value = gas_fee_reimbursement_sui.value();
    if(gas_fee_reimbursement_sui_value > 0) {
        let ten_percent = gas_fee_reimbursement_sui_value / 10;
        self.gas_fee_reimbursement_sui.join(gas_fee_reimbursement_sui.split(ten_percent));
    };

    let session_sequence_number = self.next_session_sequence_number;
    let session = DWalletSession {
        id: object::new(ctx),
        session_sequence_number,
        dwallet_network_encryption_key_id,
        consensus_validation_fee_charged_ika,
        computation_fee_charged_ika,
        gas_fee_reimbursement_sui,
    };

    let event = DWalletEvent {
        epoch: self.current_epoch,
        session_type: {
            SessionType::User {
                sequence_number: session_sequence_number,
            }
        },
        session_id: object::id(&session),
        event_data,
    };

    self.user_requested_sessions_events.add(session.id.to_inner(), event);
    self.sessions.add(session_sequence_number, session);
    self.next_session_sequence_number = session_sequence_number + 1;
    self.update_last_user_initiated_session_to_complete_in_current_epoch();

    event
}

/// Creates a new MPC session that serves the system (i.e. the Ika network).
/// The current protocols that are supported for such is network DKG and Reconfiguration,
/// both of which are related to a particular `dwallet_network_encryption_key_id`.
/// No funds are charged, since there is no user to charge.
fun create_system_dwallet_event<E: copy + drop + store>(
    self: &mut DWalletCoordinatorInner,
    event_data: E,
    ctx: &mut TxContext,
): DWalletEvent<E> {
    self.started_system_sessions_count = self.started_system_sessions_count + 1;

    let event = DWalletEvent {
        epoch: self.current_epoch,
        session_type: SessionType::System,
        session_id: object::id_from_address(tx_context::fresh_object_address(ctx)),
        event_data,
    };

    event
}

fun get_active_dwallet_and_public_output(
    self: &DWalletCoordinatorInner,
    dwallet_id: ID,
): (&DWallet, vector<u8>) {
    assert!(self.dwallets.contains(dwallet_id), EDWalletNotExists);
    let dwallet = self.dwallets.borrow(dwallet_id);
    let public_output = dwallet.validate_active_and_get_public_output();
    (dwallet, *public_output)
}

fun get_active_dwallet_and_public_output_mut(
    self: &mut DWalletCoordinatorInner,
    dwallet_id: ID,
): (&mut DWallet, vector<u8>) {
    assert!(self.dwallets.contains(dwallet_id), EDWalletNotExists);
    let dwallet = self.dwallets.borrow_mut(dwallet_id);
    let public_output = dwallet.validate_active_and_get_public_output();
    (dwallet, *public_output)
}

/// Get the active encryption key ID by its address.
public(package) fun get_active_encryption_key(
    self: &DWalletCoordinatorInner,
    address: address,
): ID {
    assert!(self.encryption_keys.contains(address), EEncryptionKeyNotExist);
    self.encryption_keys.borrow(address).id.to_inner()
}

/// Validates the `curve` selection is both supported, and not paused.
fun validate_curve(
    self: &DWalletCoordinatorInner,
    curve: u32,
) {
    assert!(self.supported_curves_to_signature_algorithms_to_hash_schemes.contains(&curve), EInvalidCurve);

    assert!(!self.paused_curves.contains(&curve), ECurvePaused);
}

/// Validates the `curve` and `signature_algorithm` selection is supported, and not paused.
fun validate_curve_and_signature_algorithm(
    self: &DWalletCoordinatorInner,
    curve: u32,
    signature_algorithm: u32,
) {
    self.validate_curve(curve);
    let supported_curve_to_signature_algorithms = self.supported_curves_to_signature_algorithms_to_hash_schemes[&curve];

    assert!(supported_curve_to_signature_algorithms.contains(&signature_algorithm), EInvalidSignatureAlgorithm);
    assert!(!self.paused_signature_algorithms.contains(&signature_algorithm), ESignatureAlgorithmPaused);
}

/// Validates the `curve`, `signature_algorithm` and `hash_scheme` selection is supported, and not paused.
fun validate_curve_and_signature_algorithm_and_hash_scheme(
    self: &DWalletCoordinatorInner,
    curve: u32,
    signature_algorithm: u32,
    hash_scheme: u32,
) {
    self.validate_curve_and_signature_algorithm(curve, signature_algorithm);
    let supported_hash_schemes = self.supported_curves_to_signature_algorithms_to_hash_schemes[&curve][&signature_algorithm];

    assert!(supported_hash_schemes.contains(&hash_scheme), EInvalidHashScheme);
    assert!(!self.paused_hash_schemes.contains(&hash_scheme), EHashSchemePaused);
}

/// Registers an encryption key to be used later for encrypting a
/// centralized secret key share.
///
/// ### Parameters
/// - `encryption_key`: The serialized encryption key to be registered.
/// - `encryption_key_signature`: The signature of the encryption key, signed by the signer.
/// - `signer_public_key`: The public key of the signer used to verify the encryption key signature.
/// - `encryption_key_scheme`: The scheme of the encryption key (e.g., Class Groups).
/// Needed so the TX will get ordered in consensus before getting executed.
public(package) fun register_encryption_key(
    self: &mut DWalletCoordinatorInner,
    curve: u32,
    encryption_key: vector<u8>,
    encryption_key_signature: vector<u8>,
    signer_public_key: vector<u8>,
    ctx: &mut TxContext
) {
    self.validate_curve(curve);
    assert!(
        ed25519_verify(&encryption_key_signature, &signer_public_key, &encryption_key),
        EInvalidEncryptionKeySignature
    );
    let signer_address = address::ed25519_address(signer_public_key);

    let id = object::new(ctx);

    let encryption_key_id = id.to_inner();

    self.encryption_keys.add(signer_address, EncryptionKey {
        id,
        created_at_epoch: self.current_epoch,
        curve,
        encryption_key,
        encryption_key_signature,
        signer_public_key,
        signer_address,
    });

    // Emit an event to signal the creation of the encryption key
    event::emit(CreatedEncryptionKeyEvent {
        encryption_key_id,
        signer_address,
    });
}

/// Represents a message that was approved to be signed by the dWallet corresponding to `dwallet_id`.
///
/// ### Fields
/// - **`dwallet_id`**: The identifier of the dWallet
///   associated with this approval.
/// - **`hash_scheme`**: The message hash scheme to use for signing.
/// - **`signature_algorithm`**: The signature algorithm with which the message can be signed.
/// - **`message`**: The message that has been approved.
public struct MessageApproval has store, drop {
    dwallet_id: ID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
}

/// Represents a message that was approved to be signed by the imported key dWallet corresponding to `dwallet_id`.
///
/// ### Fields
/// - **`dwallet_id`**: The identifier of the dWallet
///   associated with this approval.
/// - **`hash_scheme`**: The message hash scheme to use for signing.
/// - **`signature_algorithm`**: The signature algorithm with which the message can be signed.
/// - **`message`**: The message that has been approved.
public struct ImportedKeyMessageApproval has store, drop {
    dwallet_id: ID,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
}

/// Approves `message` to be signed by the dWallet corresponding to `dwallet_cap`.
/// Binds the approval for a specific `signature_algorithm` and `hash_scheme` choice.
public(package) fun approve_message(
    self: &DWalletCoordinatorInner,
    dwallet_cap: &DWalletCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>
): MessageApproval {
    let dwallet_id = dwallet_cap.dwallet_id;

    let is_imported_key_dwallet = self.validate_approve_message(dwallet_id, signature_algorithm, hash_scheme);
    assert!(!is_imported_key_dwallet, EImportedKeyDWallet);

    let approval = MessageApproval {
        dwallet_id,
        signature_algorithm,
        hash_scheme,
        message,
    };

    approval
}

/// Approves `message` to be signed by the imported key dWallet corresponding to `imported_key_dwallet_cap`.
/// Binds the approval for a specific `signature_algorithm` and `hash_scheme` choice.
public(package) fun approve_imported_key_message(
    self: &DWalletCoordinatorInner,
    imported_key_dwallet_cap: &ImportedKeyDWalletCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>
): ImportedKeyMessageApproval {
    let dwallet_id = imported_key_dwallet_cap.dwallet_id;

    let is_imported_key_dwallet = self.validate_approve_message(dwallet_id, signature_algorithm, hash_scheme);
    assert!(is_imported_key_dwallet, ENotImportedKeyDWallet);

    let approval = ImportedKeyMessageApproval {
        dwallet_id,
        signature_algorithm,
        hash_scheme,
        message,
    };

    approval
}

/// Perform shared validation for both the dWallet and imported key dWallet's variants of `approve_message()`.
/// Verify the `curve`, `signature_algorithm` and `hash_scheme` choice, and that the dWallet exists.
/// Returns whether this is an imported key dWallet, to be verified by the caller.
fun validate_approve_message(
    self: &DWalletCoordinatorInner,
    dwallet_id: ID,
    signature_algorithm: u32,
    hash_scheme: u32,
): bool {
    let (dwallet, _) = self.get_active_dwallet_and_public_output(dwallet_id);

    self.validate_curve_and_signature_algorithm_and_hash_scheme(dwallet.curve, signature_algorithm, hash_scheme);

    dwallet.is_imported_key_dwallet
}

/// Starts the first Distributed Key Generation (DKG) session.
///
/// This function creates a new `DWalletCap` object,
/// transfers it to the session initiator (the user),
/// and emits a `DWalletDKGFirstRoundRequestEvent` to signal
/// the beginning of the DKG process.
///
/// ### Parameters
///
/// ### Effects
/// - Generates a new `DWalletCap` object.
/// - Transfers the `DWalletCap` to the session initiator (`ctx.sender`).
/// - Creates a new `DWallet` object and inserts it into the `dwallets` map.
/// - Emits a `DWalletDKGFirstRoundRequestEvent`.
public(package) fun request_dwallet_dkg_first_round(
    self: &mut DWalletCoordinatorInner,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext
): DWalletCap {
    self.validate_curve(curve);

    let mut pricing_value = self.pricing.try_get_dwallet_pricing_value(curve, option::none(), DKG_FIRST_ROUND_PROTOCOL_FLAG);
    assert!(pricing_value.is_some(), EMissingProtocolPricing);

    // TODO(@Omer): check the state of the dWallet (i.e., not waiting for dkg.)
    // TODO(@Omer): I believe the best thing would be to always use the latest key. I'm not sure why the user should even supply the id.
    assert!(self.dwallet_network_encryption_keys.contains(dwallet_network_encryption_key_id), EDWalletNetworkEncryptionKeyNotExist);

    // Create a new `DWalletCap` object.
    let id = object::new(ctx);
    let dwallet_id = id.to_inner();
    let dwallet_cap = DWalletCap {
        id: object::new(ctx),
        dwallet_id,
    };
    let dwallet_cap_id = object::id(&dwallet_cap);

    // Create a new `DWallet` object,
    // link it to the `dwallet_cap` we just created by id,
    // and insert it into the `dwallets` map.
    self.dwallets.add(dwallet_id, DWallet {
        id,
        created_at_epoch: self.current_epoch,
        curve,
        public_user_secret_key_share: option::none(),
        dwallet_cap_id,
        dwallet_network_encryption_key_id,
        is_imported_key_dwallet: false,
        encrypted_user_secret_key_shares: object_table::new(ctx),
        sign_sessions: object_table::new(ctx),
        state: DWalletState::DKGRequested,
    });


    // Emit an event to request the Ika network to start DKG for this dWallet.
    event::emit(self.charge_and_create_current_epoch_dwallet_event(
                dwallet_network_encryption_key_id,
        pricing_value.extract(),
        payment_ika,
        payment_sui,
        DWalletDKGFirstRoundRequestEvent {
            dwallet_id,
            dwallet_cap_id,
            dwallet_network_encryption_key_id,
            curve,
        },
        ctx,
    ));

    dwallet_cap
}
/// Updates the `last_user_initiated_session_to_complete_in_current_epoch` field:
///  - If we already locked this field, we do nothing.
///  - Otherwise, we take the latest session whilst assuring
///    a maximum of `max_active_sessions_buffer` sessions to be completed in the current epoch.
fun update_last_user_initiated_session_to_complete_in_current_epoch(self: &mut DWalletCoordinatorInner) {
    if (self.locked_last_user_initiated_session_to_complete_in_current_epoch) {
        return
    };

    let new_last_user_initiated_session_to_complete_in_current_epoch = (
        self.number_of_completed_user_initiated_sessions + self.max_active_sessions_buffer
    ).min(
        self.next_session_sequence_number - 1
    );

    // Sanity check: only update this field if we need to.
    if (self.last_user_initiated_session_to_complete_in_current_epoch >= new_last_user_initiated_session_to_complete_in_current_epoch) {
        return
    };
    self.last_user_initiated_session_to_complete_in_current_epoch = new_last_user_initiated_session_to_complete_in_current_epoch;
}

/// Check whether all the user-initiated session that should complete in the current epoch are in fact completed.
/// This check is only relevant after `last_user_initiated_session_to_complete_in_current_epoch` is locked, and is called
/// as a requirement to advance the epoch.
/// Session sequence numbers are sequential, so ch
public(package) fun all_current_epoch_user_initiated_sessions_completed(self: &DWalletCoordinatorInner): bool {
    return true
    // return (self.locked_last_user_initiated_session_to_complete_in_current_epoch &&
    //     (self.number_of_completed_user_initiated_sessions == self.last_user_initiated_session_to_complete_in_current_epoch) &&
    //     (self.completed_system_sessions_count == self.started_system_sessions_count))
}
