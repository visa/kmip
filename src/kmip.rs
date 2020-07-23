// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::string::String;
use alloc::vec;

use num_traits::FromPrimitive;
use ttlv::{Error as TtlvError, Ttlv, Value::*};

pub use crate::constants::{enumerations::*, Tag};

pub const KMIP_PROTOCOL_VERSION: (i32, i32) = (1, 3);

#[derive(Debug)]
pub enum Error {
    Ttlv(TtlvError),
    RequestFailed(ResultReason, String),
    UnsupportedAlgorithm,
}

impl From<TtlvError> for Error {
    fn from(e: TtlvError) -> Self {
        Error::Ttlv(e)
    }
}

pub fn request<'a>(
    credentials: Option<(&'a str, &'a str)>,
    (operation, payload): (Operation, Ttlv<'a>),
) -> Ttlv<'a> {
    let mut request_header = vec![Ttlv::new(
        Tag::ProtocolVersion,
        Structure(vec![
            Ttlv::new(Tag::ProtocolVersionMajor, Integer(KMIP_PROTOCOL_VERSION.0)),
            Ttlv::new(Tag::ProtocolVersionMinor, Integer(KMIP_PROTOCOL_VERSION.1)),
        ]),
    )];

    if let Some((username, password)) = credentials {
        request_header.push(Ttlv::new(
            Tag::Authentication,
            Structure(vec![Ttlv::new(
                Tag::Credential,
                Structure(vec![
                    Ttlv::new(
                        Tag::CredentialType,
                        Enumeration(CredentialType::UsernamePassword as u32),
                    ),
                    Ttlv::new(
                        Tag::CredentialValue,
                        Structure(vec![
                            Ttlv::new(Tag::Username, TextString(username)),
                            Ttlv::new(Tag::Password, TextString(password)),
                        ]),
                    ),
                ]),
            )]),
        ));
    }

    request_header.push(Ttlv::new(Tag::BatchCount, Integer(1)));

    Ttlv::new(
        Tag::RequestMessage,
        Structure(vec![
            Ttlv::new(Tag::RequestHeader, Structure(request_header)),
            Ttlv::new(
                Tag::BatchItem,
                Structure(vec![
                    Ttlv::new(Tag::Operation, Enumeration(operation as u32)),
                    payload,
                ]),
            ),
        ]),
    )
}

pub fn locate(key_name: &str) -> (Operation, Ttlv) {
    let payload = Ttlv::new(
        Tag::RequestPayload,
        Structure(vec![Ttlv::new(
            Tag::Attribute,
            Structure(vec![
                Ttlv::new(Tag::AttributeName, TextString("Name")),
                Ttlv::new(
                    Tag::AttributeValue,
                    Structure(vec![
                        Ttlv::new(Tag::NameValue, TextString(key_name)),
                        Ttlv::new(
                            Tag::NameType,
                            Enumeration(Name::UninterpretedTextString as u32),
                        ),
                    ]),
                ),
            ]),
        )]),
    );
    (Operation::Locate, payload)
}

pub fn get(uuid: &str) -> (Operation, Ttlv) {
    let payload = Ttlv::new(
        Tag::RequestPayload,
        Structure(vec![Ttlv::new(Tag::UniqueIdentifier, TextString(uuid))]),
    );
    (Operation::Get, payload)
}

pub fn crypt<'a>(
    uuid: &'a str,
    cipher_mode: BlockCipherMode,
    data: &'a [u8],
    iv: &'a [u8],
    padding: bool,
    encrypt: bool,
) -> (Operation, Ttlv<'a>) {
    let operation = if encrypt {
        Operation::Encrypt
    } else {
        Operation::Decrypt
    };
    let padding = if padding {
        PaddingMethod::Pkcs5
    } else {
        PaddingMethod::None
    };

    let crypto_params = vec![
        Ttlv::new(Tag::BlockCipherMode, Enumeration(cipher_mode as u32)),
        Ttlv::new(Tag::PaddingMethod, Enumeration(padding as u32)),
    ];
    let payload = Ttlv::new(
        Tag::RequestPayload,
        Structure(vec![
            Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
            Ttlv::new(Tag::CryptographicParameters, Structure(crypto_params)),
            Ttlv::new(Tag::Data, ByteString(data)),
            Ttlv::new(Tag::IvCounterNonce, ByteString(iv)),
        ]),
    );
    (operation, payload)
}

pub fn auth_crypt<'a>(
    uuid: &'a str,
    data: &'a [u8],
    iv: &'a [u8],
    additional_data: Option<&'a [u8]>,
    auth_tag: Option<&'a [u8]>,
    tag_length: usize,
    encrypt: bool,
) -> (Operation, Ttlv<'a>) {
    let operation = if encrypt {
        Operation::Encrypt
    } else {
        Operation::Decrypt
    };

    let crypto_params = vec![
        Ttlv::new(
            Tag::BlockCipherMode,
            Enumeration(BlockCipherMode::Gcm as u32),
        ),
        Ttlv::new(Tag::TagLength, Integer(tag_length as i32)),
    ];
    let mut payload_items = vec![
        Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
        Ttlv::new(Tag::CryptographicParameters, Structure(crypto_params)),
        Ttlv::new(Tag::Data, ByteString(data)),
        Ttlv::new(Tag::IvCounterNonce, ByteString(iv)),
    ];
    if let Some(ad) = additional_data {
        payload_items.push(Ttlv::new(
            Tag::AuthenticatedEncryptionAdditionalData,
            ByteString(ad),
        ));
    }
    if let Some(tag) = auth_tag {
        assert!(!encrypt);
        assert_eq!(tag_length, tag.len());
        payload_items.push(Ttlv::new(Tag::AuthenticatedEncryptionTag, ByteString(tag)));
    }

    (
        operation,
        Ttlv::new(Tag::RequestPayload, Structure(payload_items)),
    )
}

pub fn hmac<'a>(uuid: &'a str, data: &'a [u8]) -> (Operation, Ttlv<'a>) {
    let payload = Ttlv::new(
        Tag::RequestPayload,
        Structure(vec![
            Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
            Ttlv::new(
                Tag::CryptographicParameters,
                Structure(vec![Ttlv::new(
                    Tag::CryptographicAlgorithm,
                    Enumeration(CryptographicAlgorithm::HmacSha256 as u32),
                )]),
            ),
            Ttlv::new(Tag::Data, ByteString(data)),
        ]),
    );
    (Operation::Mac, payload)
}

pub fn collect_response_payload<'a>(response: &'a Ttlv) -> Result<&'a Ttlv<'a>, Error> {
    let _response_header = response.path(&[Tag::ResponseHeader])?;
    let batch_item = response.path(&[Tag::BatchItem])?;
    let status: u32 = batch_item.path(&[Tag::ResultStatus])?.value()?;

    if status == ResultStatus::Success as u32 {
        let payload = batch_item.path(&[Tag::ResponsePayload])?;
        Ok(payload)
    } else {
        let reason = batch_item.path(&[Tag::ResultReason])?.value()?;
        let reason = ResultReason::from_u32(reason).unwrap_or(ResultReason::GeneralFailure);
        let message: &str = match batch_item.path(&[Tag::ResultMessage]) {
            Ok(message) => message.value()?,
            Err(_) => "No Message",
        };
        Err(Error::RequestFailed(reason, String::from(message)))
    }
}

pub fn collect_uuid<'a>(payload: &'a Ttlv) -> Result<&'a str, Error> {
    let uuid: &str = payload.path(&[Tag::UniqueIdentifier])?.value()?;
    Ok(uuid)
}

pub fn collect_data<'a>(payload: &'a Ttlv) -> Result<&'a [u8], Error> {
    let data: &[u8] = payload.path(&[Tag::Data])?.value()?;
    Ok(data)
}

pub fn collect_auth_tag<'a>(payload: &'a Ttlv) -> Result<&'a [u8], Error> {
    let auth_tag: &[u8] = payload.path(&[Tag::AuthenticatedEncryptionTag])?.value()?;
    Ok(auth_tag)
}

pub fn collect_mac_data<'a>(payload: &'a Ttlv) -> Result<&'a [u8], Error> {
    let mac_data: &[u8] = payload.path(&[Tag::MacData])?.value()?;
    Ok(mac_data)
}

pub fn collect_symmetric_key<'a>(
    payload: &'a Ttlv,
) -> Result<(&'a [u8], CryptographicAlgorithm, usize), Error> {
    let key = payload.path(&[Tag::SymmetricKey, Tag::KeyBlock])?;
    let key_material = key.path(&[Tag::KeyValue, Tag::KeyMaterial])?.value()?;
    let alg = key.path(&[Tag::CryptographicAlgorithm])?.value()?;
    let alg = CryptographicAlgorithm::from_u32(alg).ok_or(Error::UnsupportedAlgorithm)?;
    let len: i32 = key.path(&[Tag::CryptographicLength])?.value()?;

    Ok((key_material, alg, len as usize))
}
