//#![deny(missing_docs)]
//#![deny(warnings)]

//! This library is usefull for developing C/C++ AWS Nitro Enclave applications
//! with custom functionality like enclave-to-enclave
//! secure communication and mutual attestation.
//!
//!

use std::fmt;
use std::string::String;

use aws_cose::error::COSEError;
use aws_nitro_enclaves_cose as aws_cose;
use hex;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(feature = "openssl_native")
))]
use webpki;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json;

use chrono::prelude::*;
use chrono::serde::ts_milliseconds;
use chrono::{DateTime, Duration, Utc};

use itertools::Itertools;
use std::collections::HashMap;

use x509_parser::prelude::*;

use openssl::bn::BigNumContext;
use openssl::ec::*;
use openssl::nid::Nid;
#[cfg(any(
    target_arch = "wasm32",
    feature = "openssl_native"
))]
use openssl::x509;
#[cfg(any(
    target_arch = "wasm32",
    feature = "openssl_native"
))]
use openssl::x509::*;
#[cfg(any(
    target_arch = "wasm32",
    feature = "openssl_native"
))]
use openssl::stack::Stack;
#[cfg(any(
    target_arch = "wasm32",
    feature = "openssl_native"
))]
use openssl::asn1::{Asn1Time};


#[cfg(all(
    not(target_arch = "wasm32"),
    not(feature = "openssl_native")
))]
static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    #[cfg(feature = "alloc")]
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

#[derive(Debug, Serialize, Deserialize)]
struct NitroAdDocPayload {
    module_id: String,
    digest: String,

    #[serde(with = "ts_milliseconds")]
    timestamp: DateTime<Utc>,

    #[serde(serialize_with = "ser_peer_public")]
    pcrs: HashMap<u8, ByteBuf>,

    #[serde(skip_serializing)]
    certificate: ByteBuf,

    #[serde(skip_serializing)]
    cabundle: Vec<ByteBuf>,

    // optional
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<ByteBuf>,

    // optional
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<ByteBuf>,

    // optional
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<ByteBuf>,
}

fn ser_peer_public<S>(peer_public: &HashMap<u8, ByteBuf>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let map = peer_public
        .iter()
        .sorted()
        .map(|(k, v)| (k, hex::encode(v.to_vec())));
    serializer.collect_map(map)
}

#[derive(Debug)]
pub enum NitroAdError {
    COSEError(COSEError),
    CBORError(serde_cbor::Error),
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(feature = "openssl_native")
    ))]
    VerificationError(webpki::Error),
    SerializationError(serde_json::Error),
    OpenSSLError(openssl::error::Error),
    OpenSSLErrorStack(openssl::error::ErrorStack),
    IOError(std::io::Error),
    InvalidUseOfRootCertificate(String),
    Error(String),
}

impl fmt::Display for NitroAdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NitroAdError: ")
    }
}

impl From<COSEError> for NitroAdError {
    fn from(err: COSEError) -> NitroAdError {
        NitroAdError::COSEError(err)
    }
}

impl From<serde_cbor::Error> for NitroAdError {
    fn from(err: serde_cbor::Error) -> NitroAdError {
        NitroAdError::CBORError(err)
    }
}

impl From<openssl::error::Error> for NitroAdError {
    fn from(err: openssl::error::Error) -> NitroAdError {
        NitroAdError::OpenSSLError(err)
    }
}

impl From<openssl::error::ErrorStack> for NitroAdError {
    fn from(err: openssl::error::ErrorStack) -> NitroAdError {
        NitroAdError::OpenSSLErrorStack(err)
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(feature = "openssl_native")
))]
impl From<webpki::Error> for NitroAdError {
    fn from(err: webpki::Error) -> NitroAdError {
        NitroAdError::VerificationError(err)
    }
}

impl From<serde_json::Error> for NitroAdError {
    fn from(err: serde_json::Error) -> NitroAdError {
        NitroAdError::SerializationError(err)
    }
}

impl From<std::io::Error> for NitroAdError {
    fn from(err: std::io::Error) -> NitroAdError {
        NitroAdError::IOError(err)
    }
}

pub struct NitroAdDoc {
    payload_ref: NitroAdDocPayload,
}


#[cfg(target_arch = "wasm32")]
type UnixTime = i32;
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "openssl_native"
))]
type UnixTime = i64;

#[cfg(any(
    target_arch = "wasm32",
    feature = "openssl_native"
))]
pub struct CertificateChainVerifier {
    root_cert: Vec<u8>,
    root_cert_x509: X509,
    peer_cert: Option<X509>,
    cert_chain: Stack<X509>,
    timestamp: Asn1Time
}

#[cfg(any(
    target_arch = "wasm32",
    feature = "openssl_native"
))]
impl CertificateChainVerifier {

    /// Validates timestamp of the certificate against the timestamp passed as a parameter in the method "new".
    /// Time should be validated manually, because there is no API end-point in OpenSSL to pass custom timestamp for validation.
    /// # Arguments
    /// * `cert` - OpenSSL::x509::X509 certificate to validate
    fn validate_time(cert: &x509::X509, timestamp: &Asn1Time) -> Result<(), NitroAdError> {

        if timestamp < cert.not_before() {
            return Err(NitroAdError::Error("CertNotValidYet.".to_owned()));
        }
        else if timestamp > cert.not_after() {
            return Err(NitroAdError::Error("CertExpired.".to_owned()));
        }

        Ok(())
    }

    /// Compares the root ca certificate with other certificates. Returns error, when certificates are equal.
    /// # Arguments
    /// * `cert` - OpenSSL::x509::X509 certificate
    fn compare_cert_with_root(&self, cert: &X509) -> Result<(), NitroAdError> {
        if cert.to_der()? == self.root_cert {
            return Err(NitroAdError::InvalidUseOfRootCertificate("Root certificate used as peer or chain certificate!".to_owned()));
        }  
        Ok(())
    }

    /// Decodes der-encoded certificate into OpenSSL::x509::X509 structure.
    /// # Arguments
    /// * `cert_der` - der-encoded certificate.
    fn der_to_x509(cert_der: &[u8]) -> Result<X509, NitroAdError> {
        Ok(X509::from_der(cert_der)?)
    }

    fn validate_root_cert(root_cert_der: &[u8], timestamp: &Asn1Time) -> Result<X509, NitroAdError> {
        let root_cert = CertificateChainVerifier::der_to_x509(root_cert_der)?;
        CertificateChainVerifier::validate_time(&root_cert, timestamp)?;
        Ok(root_cert)
    }

    /// Creates new instance of the CertificateChainVerifier
    /// # Arguments
    /// * `root_cert_der` - der-encoded root certificate
    /// * `timestamp`     - unix time
    pub fn new(root_cert_der: &[u8], timestamp: u64) -> Result<Self, NitroAdError> {

        let timestamp_asn = Asn1Time::from_unix(timestamp as UnixTime)?;
        let root_cert_x509 = CertificateChainVerifier::validate_root_cert(root_cert_der, &timestamp_asn)?;

        Ok (CertificateChainVerifier { 
            timestamp: timestamp_asn, 
            root_cert: root_cert_der.to_vec(),
            root_cert_x509: root_cert_x509,
            peer_cert: None,
            cert_chain: openssl::stack::Stack::new()?
        })
    }



    /// Adds peer certificate to the OpenSSL validation context.
    /// # Arguments
    /// * `peer_cert_der` - der-encoded peer certificate.
    pub fn add_peer_cert(&mut self, peer_cert_der: &[u8]) -> Result<(), NitroAdError> {
        let peer_cert = CertificateChainVerifier::der_to_x509(peer_cert_der)?;
        CertificateChainVerifier::validate_time(&peer_cert, &self.timestamp)?;
        self.compare_cert_with_root(&peer_cert)?;
        self.peer_cert = Some(peer_cert);
        Ok(())
    }

    /// Adds extra certificate to the chain
    /// # Arguments
    /// * `cert_der` - der-encoded certificate
    pub fn add_certificate_to_chain(&mut self, cert_der: &[u8]) -> Result<(), NitroAdError> {
        let cert = CertificateChainVerifier::der_to_x509(cert_der)?;
        CertificateChainVerifier::validate_time(&cert, &self.timestamp)?;
        self.compare_cert_with_root(&cert)?;
        self.cert_chain.push(cert)?;
        Ok(())
    }

    /// Validates certificate chain against the root certificate
    pub fn validate(self) -> Result<(), NitroAdError> {
        let mut store_ctx = x509::X509StoreContext::new()?;

        let mut store_builder = x509::store::X509StoreBuilder::new()?;
        store_builder.set_flags(x509::verify::X509VerifyFlags::NO_CHECK_TIME)?; 
        store_builder.add_cert(self.root_cert_x509)?;
        let store = store_builder.build();        

        match store_ctx.init(&store, &self.peer_cert.unwrap(), &self.cert_chain, |c| c.verify_cert())? {
            true => Ok(()),
            false => Err(NitroAdError::Error(format!("Certificate validation failed: {}", store_ctx.error())))
        }
    }
}

impl NitroAdDoc {
    pub fn from_bytes(
        bytes: &[u8],
        root_cert: &[u8],
        unix_ts_sec: u64,
    ) -> Result<Self, NitroAdError> {
        let ad_doc_cose = aws_cose::COSESign1::from_bytes(bytes)?;

        // for validation flow details see here:
        // https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

        // no Signature checks for now - no key specified 
        let ad_payload = ad_doc_cose.get_payload(None)?;
        let ad_parsed: NitroAdDocPayload = serde_cbor::from_slice(&ad_payload)?;

        (ad_parsed.module_id.len() > 0)
            .then(|| ())
            .ok_or(NitroAdError::Error(String::from("module_id is empty")))?;

        (ad_parsed.digest == "SHA384")
            .then(|| ())
            .ok_or(NitroAdError::Error(String::from(
                "digest signature is unknown",
            )))?;

        // validate timestamp range
        let ts_start = Utc.ymd(2020, 1, 1).and_hms(0, 0, 0);
        let ts_end = Utc::now() + Duration::days(1);
        (ad_parsed.timestamp > ts_start && ad_parsed.timestamp < ts_end)
            .then(|| ())
            .ok_or(NitroAdError::Error(String::from(
                "timestamp field has wrong value",
            )))?;

        // validate pcr map length
        let pcrs_len = ad_parsed.pcrs.len() as u8;
        ((1..32).contains(&pcrs_len))
            .then(|| ())
            .ok_or(NitroAdError::Error(String::from(
                "wrong number of PCRs in the map",
            )))?;

        // validate pcr items
        for i in 0..pcrs_len {
            (ad_parsed.pcrs.contains_key(&i))
                .then(|| ())
                .ok_or(NitroAdError::Error(format!("PCR{} is missing", i)))?;

            let pcr_len = ad_parsed.pcrs[&i].len();
            ([32, 48, 64].contains(&pcr_len))
                .then(|| ())
                .ok_or(NitroAdError::Error(format!(
                    "PCR{} len is other than 32/48/64 bytes",
                    i
                )))?;
            //println!("prc{:2}:  {}", i, hex::encode( ad_parsed.pcrs[&i].to_vec() ) );
        }

        // validate 'certificate' member against
        // 'cabundle' with root cert replaced with our trusted hardcoded one
        let ee: &[u8] = &ad_parsed.certificate; // the public key certificate for the public key that was used to sign the attestation document

        let mut interm: Vec<ByteBuf> = ad_parsed.cabundle.clone(); // issuing CA bundle for infrastructure certificate
        let interm = &mut interm[1..]; // skip first (claimed root) cert

        #[cfg(all(
            not(target_arch = "wasm32"),
            not(feature = "openssl_native")
        ))]
        {
            let interm_slices: Vec<_> = interm.iter().map(|x| x.as_slice()).collect();
            let interm_slices: &[&[u8]] = &interm_slices.to_vec();
            
            let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(root_cert).unwrap()];
            let anchors = webpki::TLSServerTrustAnchors(&anchors);
            
            let time = webpki::Time::from_seconds_since_unix_epoch(unix_ts_sec);
            
            let cert = webpki::EndEntityCert::from(ee)?;
            cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, interm_slices, time)?;
        }
        
        #[cfg(any(
            target_arch = "wasm32",
            feature = "openssl_native"
        ))]
        {
            let mut cert_chain_verifier = CertificateChainVerifier::new(root_cert, unix_ts_sec)?;
            cert_chain_verifier.add_peer_cert(ee)?;

            for i in interm {
                cert_chain_verifier.add_certificate_to_chain(&i.to_vec())?;
            }
            cert_chain_verifier.validate()?;

        }        

        let res = parse_x509_certificate(ee);
        match res {
            Ok((rem, cert)) => {
                (rem.is_empty())
                    .then(|| ())
                    .ok_or(NitroAdError::Error(String::from("rem isnot empty")))?;

                (cert.tbs_certificate.version == X509Version::V3)
                    .then(|| ())
                    .ok_or(NitroAdError::Error(String::from("wrong cert version")))?;

                let ee_pub_key = cert.tbs_certificate.subject_pki.subject_public_key.data;

                let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
                let mut ctx = BigNumContext::new().unwrap();
                let point = EcPoint::from_bytes(&group, &ee_pub_key, &mut ctx).unwrap();
                let key = EcKey::from_public_key(&group, &point).unwrap();

                // [TODO] remove all above parse_x509_certificate() stuff and extract public key with webpki after issue
                // https://github.com/briansmith/webpki/issues/85
                // become fixed

                if !ad_doc_cose.verify_signature(&key)? {
                    return Err(NitroAdError::COSEError(COSEError::UnimplementedError));  //should be SignatureError(openssl::error::ErrorStack)
                }
            }
            _ => {
                return Err(NitroAdError::Error(format!(
                    "x509 parsing failed: {:?}",
                    res
                )))
            }
        }

        Ok(NitroAdDoc {
            payload_ref: ad_parsed,
        })
    }

    pub fn to_json(&self) -> Result<String, NitroAdError> {
        let str = serde_json::to_string(&self.payload_ref)?;

        Ok(str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_to_valid_json() -> Result<(), NitroAdError> {

        // current ee cert baked into the ../tests/data/nitro_ad_debug.bin attestation document has next time limits
        //
        // notBefore=Mar  5 17:01:49 2021 GMT
        // notAfter=Mar  5 20:01:49 2021 GMT
        //
        // let's substitute test timestamp within above range
        // Use next snippet to export cert
        //
        //let mut f = File::create("./_ee.der").expect("Could not run file!");
        //f.write_all(ee);
        //
        // Then, issue next cmd to see notBefore & notAfter from ./_ee.der
        // $openssl x509 -startdate -enddate -noout -inform der -in ./_ee.der

        
        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");

        let nitro_addoc = NitroAdDoc::from_bytes(ad_blob, root_cert, 1614967200)?; // Mar 5 18:00:00 2021 GMT
        let js = nitro_addoc.to_json().unwrap();

        let _: serde::de::IgnoredAny = serde_json::from_str(&js)?;  // test js is valid JSON string (by trying to parse it)

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_broken_root_cert() { 

        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");
        let mut root_cert_copy = root_cert.clone();

        root_cert_copy[200] = 0xff;
        let _nitro_addoc = NitroAdDoc::from_bytes(ad_blob, &root_cert_copy, 1614967200).unwrap(); // Mar 5 18:00:00 2021 GMT
    }

    #[test]
    #[should_panic]
    fn test_expired_ee_cert() { 

        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");
        let _nitro_addoc = NitroAdDoc::from_bytes(ad_blob, root_cert, 1618407754).unwrap(); 
    }

    #[test]
    #[should_panic]
    fn test_notyetvalid_ee_cert() { 

        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");
        let _nitro_addoc = NitroAdDoc::from_bytes(ad_blob, root_cert, 1614947200).unwrap(); 
    }

    #[test]
    #[should_panic]
    fn test_broken_some_cert_in_ad() { 

        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");
        let mut ad_blob_copy = ad_blob.clone();

        ad_blob_copy[0x99f] = 0xff;
        let _nitro_addoc = NitroAdDoc::from_bytes(&ad_blob_copy, root_cert, 1614967200).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_broken_ad_pcrx() { 

        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");
        let mut ad_blob_copy = ad_blob.clone();

        ad_blob_copy[0x13b] = 0xff;
        let _nitro_addoc = NitroAdDoc::from_bytes(&ad_blob_copy, root_cert, 1614967200).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_broken_ad_debug_pcrx() {   // mutate zero-filled PCR

        let ad_blob = include_bytes!("../tests/data/nitro_ad_debug.bin");
        let root_cert = include_bytes!("../tests/data/aws_root.der");
        let mut ad_blob_copy = ad_blob.clone();

        ad_blob_copy[0x281] = 0xff;
        let _nitro_addoc = NitroAdDoc::from_bytes(&ad_blob_copy, root_cert, 1614967200).unwrap();
    }

    #[test]
    fn cose_sign1_ec384_validate() {
        let (_, ec_public) = get_ec384_test_key();

        const TEXT: &[u8] = b"It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife.";

        // This output was validated against COSE-C implementation
        let cose_doc = aws_cose::COSESign1::from_bytes(&[
            0x84, /* Protected: {1: -35} */
            0x44, 0xA1, 0x01, 0x38, 0x22, /* Unprotected: {4: '11'} */
            0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
            0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
            0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
            0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
            0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
            0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
            0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
            0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
            0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E, /* signature - length 48 x 2 */
            0x58, 0x60, /* R: */
            0xCD, 0x42, 0xD2, 0x76, 0x32, 0xD5, 0x41, 0x4E, 0x4B, 0x54, 0x5C, 0x95, 0xFD, 0xE6,
            0xE3, 0x50, 0x5B, 0x93, 0x58, 0x0F, 0x4B, 0x77, 0x31, 0xD1, 0x4A, 0x86, 0x52, 0x31,
            0x75, 0x26, 0x6C, 0xDE, 0xB2, 0x4A, 0xFF, 0x2D, 0xE3, 0x36, 0x4E, 0x9C, 0xEE, 0xE9,
            0xF9, 0xF7, 0x95, 0xA0, 0x15, 0x15, /* S: */
            0x5B, 0xC7, 0x12, 0xAA, 0x28, 0x63, 0xE2, 0xAA, 0xF6, 0x07, 0x8A, 0x81, 0x90, 0x93,
            0xFD, 0xFC, 0x70, 0x59, 0xA3, 0xF1, 0x46, 0x7F, 0x64, 0xEC, 0x7E, 0x22, 0x1F, 0xD1,
            0x63, 0xD8, 0x0B, 0x3B, 0x55, 0x26, 0x25, 0xCF, 0x37, 0x9D, 0x1C, 0xBB, 0x9E, 0x51,
            0x38, 0xCC, 0xD0, 0x7A, 0x19, 0x31,
        ])
        .unwrap();

        assert_eq!(cose_doc.get_payload(Some(&ec_public)).unwrap(), TEXT);
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        not(feature = "openssl_native")
    ))]
    #[test]
    fn aws_root_cert_used_as_end_entity_cert() {
        let ee: &[u8] = include_bytes!("../tests/data/aws_root.der");
        let ca = include_bytes!("../tests/data/aws_root.der");

        let anchors = vec![webpki::trust_anchor_util::cert_der_as_trust_anchor(ca).unwrap()];
        let anchors = webpki::TLSServerTrustAnchors(&anchors);

        let time = webpki::Time::from_seconds_since_unix_epoch(1616094379); // 18 March 2021

        let cert = webpki::EndEntityCert::from(ee).unwrap();
        assert_eq!(
            Err(webpki::Error::CAUsedAsEndEntity),
            cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)
        );
    }

    // [TODO] this test fails, because openssl allows to pass ca certificate as an end-entity certificate. Maybe it should be checked manually before openssl validation.
    #[cfg(any(
        target_arch = "wasm32",
        feature = "openssl_native"
    ))]
    #[test]
    fn aws_root_cert_used_as_end_entity_cert() {
        let ee: &[u8] = include_bytes!("../tests/data/aws_root.der");
        let ca = include_bytes!("../tests/data/aws_root.der");

        let mut cert_chain_verifier = CertificateChainVerifier::new(ca, 1616094379).unwrap();
        match cert_chain_verifier.add_peer_cert(ee) {
            Err(NitroAdError::InvalidUseOfRootCertificate(_)) => {},
            _ => panic!("Test failed")
        }      
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    use openssl::pkey::{Private, Public};

    /// Static SECP384R1/P-384 key to be used when cross-validating the implementation
    fn get_ec384_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let x = openssl::bn::BigNum::from_hex_str(
            "5a829f62f2f4f095c0e922719285b4b981c677912870a413137a5d7319916fa8\
                584a6036951d06ffeae99ca73ab1a2dc",
        )
        .unwrap();
        let y = openssl::bn::BigNum::from_hex_str(
            "e1b76e08cb20d6afcea7423f8b49ec841dde6f210a6174750bf8136a31549422\
                4df153184557a6c29a1d7994804f604c",
        )
        .unwrap();
        let d = openssl::bn::BigNum::from_hex_str(
            "55c6aa815a31741bc37f0ffddea73af2397bad640816ef22bfb689efc1b6cc68\
                2a73f7e5a657248e3abad500e46d5afc",
        )
        .unwrap();
        let ec_public =
            openssl::ec::EcKey::from_public_key_affine_coordinates(&alg, &x, &y).unwrap();
        let ec_private =
            openssl::ec::EcKey::from_private_components(&alg, &d, &ec_public.public_key()).unwrap();
        (
            //PKey::from_ec_key(ec_private).unwrap(),
            //PKey::from_ec_key(ec_public).unwrap(),
            ec_private, ec_public,
        )
    }
}
