// SPDX-License-Identifier: MIT OR Apache-2.0

use num_derive::{FromPrimitive, ToPrimitive};

#[derive(Copy, Clone, PartialEq, Debug, FromPrimitive, ToPrimitive)]
pub enum Tag {
    Attribute = 0x0008,
    AttributeName = 0x000A,
    AttributeValue = 0x000B,
    Authentication = 0x000C,
    BatchCount = 0x000D,
    BatchItem = 0x000F,
    BlockCipherMode = 0x0011,
    Credential = 0x0023,
    CredentialType = 0x0024,
    CredentialValue = 0x0025,
    CryptographicAlgorithm = 0x0028,
    CryptographicLength = 0x002A,
    CryptographicParameters = 0x002B,
    HashingAlgorithm = 0x0038,
    IvCounterNonce = 0x003D,
    KeyBlock = 0x0040,
    KeyCompressionType = 0x0041,
    KeyFormatType = 0x0042,
    KeyMaterial = 0x0043,
    KeyPartIdentifier = 0x0044,
    KeyValue = 0x0045,
    Name = 0x0053,
    NameType = 0x0054,
    NameValue = 0x0055,
    ObjectType = 0x0057,
    Operation = 0x005C,
    PaddingMethod = 0x005F,
    ProtocolVersion = 0x0069,
    ProtocolVersionMajor = 0x006A,
    ProtocolVersionMinor = 0x006B,
    RequestHeader = 0x0077,
    RequestMessage = 0x0078,
    RequestPayload = 0x0079,
    ResponseHeader = 0x007A,
    ResponseMessage = 0x007B,
    ResponsePayload = 0x007C,
    ResultMessage = 0x007D,
    ResultReason = 0x007E,
    ResultStatus = 0x007F,
    SymmetricKey = 0x008F,
    TimeStamp = 0x0092,
    UniqueBatchItemId = 0x0093,
    UniqueIdentifier = 0x0094,
    Username = 0x0099,
    Password = 0x00A1,
    Data = 0x00C2,
    DataLength = 0x00C4,
    MacData = 0x00C6,
    IvLength = 0x00CD,
    TagLength = 0x00CE,
    AuthenticatedEncryptionAdditionalData = 0x00FE,
    AuthenticatedEncryptionTag = 0x00FF,
}

// http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html#_Toc490660920
pub mod enumerations {
    use num_derive::{FromPrimitive, ToPrimitive};

    pub enum CredentialType {
        UsernamePassword = 0x0000_0001,
        Device = 0x0000_0002,
        Attestation = 0x0000_0003,
    }
    pub enum ObjectType {
        Certificate = 0x0000_0001,
        SymmetricKey = 0x0000_0002,
        PublicKey = 0x0000_0003,
        PrivateKey = 0x0000_0004,
    }
    #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive, ToPrimitive)]
    pub enum CryptographicAlgorithm {
        Aes = 0x0000_0003,
        Sm4 = 0x0000_0102,
        HmacSha256 = 0x0000_0009,
    }
    pub enum BlockCipherMode {
        Cbc = 0x0000_0001,
        Ecb = 0x0000_0002,
        Gcm = 0x0000_0009,
    }
    pub enum PaddingMethod {
        None = 0x0000_0001,
        Oaep = 0x0000_0002,
        Pkcs5 = 0x0000_0003,
    }
    pub enum HashingAlgorithm {
        Sha256 = 0x0000_0006,
        Sha384 = 0x0000_0007,
        Sha512 = 0x0000_0008,
    }
    pub enum Operation {
        Locate = 0x0000_0008,
        Get = 0x0000_000A,
        Encrypt = 0x0000_001F,
        Decrypt = 0x0000_0020,
        Mac = 0x0000_0023,
    }
    pub enum Name {
        UninterpretedTextString = 0x0000_0001,
        Uri = 0x0000_0002,
    }
    pub enum ResultStatus {
        Success = 0x0000_0000,
        Failed = 0x0000_0001,
        Pending = 0x0000_0002,
        Undone = 0x0000_0003,
    }
    #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive, ToPrimitive)]
    pub enum ResultReason {
        ItemNotFound = 0x0000_0001,
        ResponseTooLarge,
        AuthenticationNotSuccessful,
        InvalidMessage,
        OperationNotSupported,
        MissingData,
        InvalidField,
        FeatureNotSupported,
        OperationCanceled,
        CryptographicFailure,
        IllegalOperation,
        PermissionDenied,
        ObjectArchived,
        IndexOutOfBounds,
        NamespaceNotSupported,
        KeyFormatTypeNotSupported,
        KeyCompressionTypeNotSupported,
        EncodingOptionError,
        KeyValueNotPresent,
        AttestationRequired,
        AttestationFailed,
        Sensitive,
        NotExtractable,
        ObjectAlreadyExists,
        GeneralFailure = 0x0000_0100,
    }
}
