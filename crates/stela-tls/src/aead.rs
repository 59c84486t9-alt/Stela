//! TLS record adaptation of the pinned stable AEAD APIs; no primitive implementation.
use aes_gcm::aead::{AeadInOut, KeyInit};
use alloc::boxed::Box;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, Tls13AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
    make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};
#[derive(Clone, Copy)]
pub(crate) enum Algorithm {
    Aes128,
    Aes256,
    Chacha,
}
enum Cipher {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Aes256(Box<aes_gcm::Aes256Gcm>),
    Chacha(Box<chacha20poly1305::ChaCha20Poly1305>),
}
impl Cipher {
    fn new(algorithm: Algorithm, key: AeadKey) -> Self {
        match algorithm {
            Algorithm::Aes128 => Self::Aes128(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).expect("Rustls AES128 key width"),
            )),
            Algorithm::Aes256 => Self::Aes256(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).expect("Rustls AES256 key width"),
            )),
            Algorithm::Chacha => Self::Chacha(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                    .expect("Rustls ChaCha key width"),
            )),
        }
    }
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut [u8]) -> Result<[u8; 16], Error> {
        let tag = match self {
            Self::Aes128(c) => c.encrypt_inout_detached(nonce.into(), aad, bytes.into()),
            Self::Aes256(c) => c.encrypt_inout_detached(nonce.into(), aad, bytes.into()),
            Self::Chacha(c) => c.encrypt_inout_detached(nonce.into(), aad, bytes.into()),
        }
        .map_err(|_| Error::EncryptError)?;
        Ok(tag.into())
    }
    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        bytes: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        match self {
            Self::Aes128(c) => {
                c.decrypt_inout_detached(nonce.into(), aad, bytes.into(), tag.into())
            }
            Self::Aes256(c) => {
                c.decrypt_inout_detached(nonce.into(), aad, bytes.into(), tag.into())
            }
            Self::Chacha(c) => {
                c.decrypt_inout_detached(nonce.into(), aad, bytes.into(), tag.into())
            }
        }
        .map_err(|_| Error::DecryptError)
    }
}
impl Algorithm {
    fn explicit(self) -> usize {
        match self {
            Self::Chacha => 0,
            _ => 8,
        }
    }
    fn traffic(self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self {
            Self::Aes128 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::Chacha => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
    fn tls12_iv(self, fixed: &[u8], explicit: &[u8]) -> Iv {
        match self {
            Self::Chacha => Iv::copy(fixed),
            _ => {
                let mut iv = [0; 12];
                iv[..4].copy_from_slice(fixed);
                iv[4..].copy_from_slice(explicit);
                Iv::new(iv)
            }
        }
    }
}
struct Record13 {
    cipher: Cipher,
    iv: Iv,
}
impl Tls13AeadAlgorithm for Algorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Record13 {
            cipher: Cipher::new(*self, key),
            iv,
        })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Record13 {
            cipher: Cipher::new(*self, key),
            iv,
        })
    }
    fn key_len(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            _ => 32,
        }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.traffic(key, iv))
    }
}
impl MessageEncrypter for Record13 {
    fn encrypted_payload_len(&self, length: usize) -> usize {
        length + 1 + 16
    }
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total = self.encrypted_payload_len(message.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&message.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total);
        let tag = self.cipher.seal(&nonce, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }
}
impl MessageDecrypter for Record13 {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let length = message
            .payload
            .len()
            .checked_sub(16)
            .ok_or(Error::DecryptError)?;
        let tag: [u8; 16] = message.payload[length..]
            .try_into()
            .map_err(|_| Error::DecryptError)?;
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(message.payload.len());
        self.cipher
            .open(&nonce, &aad, &mut message.payload[..length], &tag)?;
        message.payload.truncate(length);
        message.into_tls13_unpadded_message()
    }
}
struct Record12 {
    cipher: Cipher,
    iv: Iv,
    explicit: usize,
}
impl Tls12AeadAlgorithm for Algorithm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Record12 {
            cipher: Cipher::new(*self, key),
            iv: self.tls12_iv(iv, extra),
            explicit: self.explicit(),
        })
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Record12 {
            cipher: Cipher::new(*self, key),
            iv: self.tls12_iv(iv, &[0; 8]),
            explicit: self.explicit(),
        })
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: if matches!(self, Self::Aes128) { 16 } else { 32 },
            fixed_iv_len: if self.explicit() == 0 { 12 } else { 4 },
            explicit_nonce_len: self.explicit(),
        }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.traffic(key, self.tls12_iv(iv, explicit)))
    }
}
impl MessageEncrypter for Record12 {
    fn encrypted_payload_len(&self, length: usize) -> usize {
        length + self.explicit + 16
    }
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total = self.encrypted_payload_len(message.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, message.typ, message.version, message.payload.len());
        if self.explicit != 0 {
            payload.extend_from_slice(&nonce[4..]);
        }
        payload.extend_from_chunks(&message.payload);
        let tag = self
            .cipher
            .seal(&nonce, &aad, &mut payload.as_mut()[self.explicit..])?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            message.typ,
            message.version,
            payload,
        ))
    }
}
impl MessageDecrypter for Record12 {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let length = message
            .payload
            .len()
            .checked_sub(self.explicit + 16)
            .ok_or(Error::DecryptError)?;
        let mut nonce = Nonce::new(&self.iv, seq).0;
        if self.explicit != 0 {
            nonce[4..].copy_from_slice(&message.payload[..8]);
        }
        let end = self.explicit + length;
        let tag: [u8; 16] = message.payload[end..]
            .try_into()
            .map_err(|_| Error::DecryptError)?;
        let aad = make_tls12_aad(seq, message.typ, message.version, length);
        self.cipher
            .open(&nonce, &aad, &mut message.payload[self.explicit..end], &tag)?;
        if length > 16384 {
            return Err(Error::PeerSentOversizedRecord);
        }
        message.payload.copy_within(self.explicit..end, 0);
        message.payload.truncate(length);
        Ok(message.into_plain_message())
    }
}
