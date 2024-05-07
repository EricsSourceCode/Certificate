// Copyright Eric Chauvin 2023.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once


// RFC 8017



#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"




class DerObjID
  {
  private:
  bool testForCopy = false;

  public:
  DerObjID( void )
    {
    }

  DerObjID( const DerObjID& in )
    {
    if( in.testForCopy )
      return;

    throw "DerObjID copy constructor called.";
    }

  ~DerObjID( void )
    {
    }

  static void makeFromCharBuf(
                        const CharBuf& inBuf,
                        CharBuf& outBuf );

  static Uint64 getOneNumber(
                        CharBuf& codedBytes );


  };


/*
// Object Identifiers.

// I got most of these from Microsoft help.
// It's in the CRYPT_ALGORITHM_IDENTIFIER
// structure.  But I've added more as I had
// to look them up.
// A string like "1.2.840.113549" is easy
// to find with a Google search.

"1.2.840.113549"] = "RSA";
"1.2.840.113549.1"] = "PKCS";
"1.2.840.113549.2"] = "RSA HASH";
"1.2.840.113549.3"] = "RSA ENCRYPT";
"1.2.840.113549.1.1"] = "PKCS 1";
"1.2.840.113549.1.2"] = "PKCS 2";
"1.2.840.113549.1.3"] = "PKCS 3";
"1.2.840.113549.1.4"] = "PKCS 4";
"1.2.840.113549.1.5"] = "PKCS 5";
"1.2.840.113549.1.6"] = "PKCS 6";
"1.2.840.113549.1.7"] = "PKCS 7";
"1.2.840.113549.1.8"] = "PKCS 8";
"1.2.840.113549.1.9"] = "PKCS 9";
"1.2.840.113549.1.10"] = "PKCS 10";
"1.2.840.113549.1.12"] = "PKCS 12";
"1.2.840.113549.1.1.2"] = "RSA_MD2";
"1.2.840.113549.1.1.3"] = "RSA_MD4";
"1.2.840.113549.1.1.4"] = "RSA_MD5";
"1.2.840.113549.1.1.1"] =
                   "RSA_RSA RSA Encryption.
                  RFC 2313, 2437, 3370.";
"1.2.840.113549.1.1.2"] = "RSA_MD2RSA";
"1.2.840.113549.1.1.3"] = "RSA_MD4RSA";
"1.2.840.113549.1.1.4"] = "RSA_MD5RSA";
"1.2.840.113549.1.1.5"] = "SHA1 with RSA.
               RSA_SHA1RSA RFC 2437, 3370";
"1.2.840.113549.1.1.6"] = "rsaOAEPEncryptionSET";
"1.2.840.113549.1.1.7"] = "id-RSAES-OAEP";
"1.2.840.113549.1.1.11"] = "SHA256 with RSA";
"1.2.840.113549.1.1.12"] = "SHA384 with RSA";
"1.2.840.113549.1.3.1"] = "RSA_DH";
"1.2.840.113549.1.7.1"] = "RSA_data";
"1.2.840.113549.1.7.2"] = "RSA_signedData";
"1.2.840.113549.1.7.3"] = "RSA_envelopedData";
"1.2.840.113549.1.7.4"] = "RSA_signEnvData";
"1.2.840.113549.1.7.5"] = "RSA_digestedData";
"1.2.840.113549.1.7.5"] = "RSA_hashedData";
"1.2.840.113549.1.7.6"] = "RSA_encryptedData";
"1.2.840.113549.1.9.1"] = "RSA_emailAddr";
"1.2.840.113549.1.9.2"] = "RSA_unstructName";
"1.2.840.113549.1.9.3"] = "RSA_contentType";
"1.2.840.113549.1.9.4"] = "RSA_messageDigest";
"1.2.840.113549.1.9.5"] = "RSA_signingTime";
"1.2.840.113549.1.9.6"] = "RSA_counterSign";
"1.2.840.113549.1.9.7"] = "RSA_challengePwd";
"1.2.840.113549.1.9.8"] = "RSA_unstructAddr";
"1.2.840.113549.1.9.9"] = "RSA_extCertAttrs";
"1.2.840.113549.1.9.15"] =
                  "RSA_SMIMECapabilities";
"1.2.840.113549.1.9.15.1"] =
                      "RSA_preferSignedData";
"1.2.840.113549.3.2"] = "RSA_RC2CBC";
"1.2.840.113549.3.4"] = "RSA_RC4";
"1.2.840.113549.3.7"] = "RSA_DES_EDE3_CBC";
"1.2.840.113549.3.9"] = "RSA_RC5_CBCPad";
"1.2.840.10046"] = "ANSI_x942";
"1.2.840.10046.2.1"] = "ANSI_x942_DH";


"1.2.840.10040"] = "X957";
"1.2.840.10040.4.1"] = "X957_DSA";
"1.2.840.10040.4.3"] = "DATA STRUCTURE";

1.2.840.10045.4.3.3
ecdsa-with-SHA384(3)
Elliptic curve Digital Signature Algorithm
 (DSA) coupled with the Secure Hash
 Algorithm 384 (SHA384) algorithm
See RFC 5480 and RFC 5758.
           DSA Digital Signature Algorithm.
https://en.wikipedia.org/wiki/Digital_Signature_Algorithm


"1.3.6.1.5.5.7.1.1"] =
                "Authority Info Access
               "The authority information
               access extension identifies
               how to access CA information
               and services. The extension
               value contains a sequence of
               URIs.\"";

"2.5"] = "DS";
// "Enables identification of the CA
 public key that corresponds to the CA
    // private key that signed an
   issued certificate. It is used by
 certificate
    // path building software on a
 Windows server to find the CA certificate.
    // When a CA issues a certificate,
 the extension value is set equal to the
    // SubjectKeyIdentifier extension
 in the CA signing certificate. The value
    // is typically a SHA-1 hash of the
 public key."
"2.5.29.1"] = "Authority key identifier";
"2.5.29.10"] = "Basic Constraints";
"2.5.29.14"] = "Subject key identifier";
"2.5.29.15"] = "Key Usage";
"2.5.29.17"] = "Subject Alt Name";
"2.5.29.19"] = "Basic Constraints";
"2.5.29.25"] = "CRL Distribution Points";
"2.5.29.31"] = "CRL Distribution Points";
"2.5.29.32"] = "Certificate Policies";
"2.5.29.35"] = "Authority key identifier";
"2.5.29.37"] =
           "Certificate Extension key usage";
"2.5.4.1"] = "Aliased Entry Name";
"2.5.4.2"] = "Knowledge Information";
"2.5.4.3"] = "Common Name";
"2.5.4.6"] = "Country Name";
"2.5.4.7"] = "Locality Name";
"2.5.4.8"] = "State or Province Name";
"2.5.4.9"] = "Street Address";
"2.5.4.10"] = "Organization Name";
"2.5.4.11"] = "Organization Unit Name";
"2.5.8"] = "DSALG";
"2.5.8.1"] = "DSALG_CRPT";
"2.5.8.2"] = "DSALG_HASH";
"2.5.8.3"] = "DSALG_SIGN";
"2.5.8.1.1"] = "DSALG_RSA";
"1.3.14"] = "OIW";
"1.3.14.3.2"] = "OIWSEC";
"1.3.14.3.2.2"] = "OIWSEC_md4RSA";
"1.3.14.3.2.3"] = "OIWSEC_md5RSA";
"1.3.14.3.2.4"] = "OIWSEC_md4RSA2";
"1.3.14.3.2.6"] = "OIWSEC_desECB";
"1.3.14.3.2.7"] = "OIWSEC_desCBC";
"1.3.14.3.2.8"] = "OIWSEC_desOFB";
"1.3.14.3.2.9"] = "OIWSEC_desCFB";
"1.3.14.3.2.10"] = "OIWSEC_desMAC";
"1.3.14.3.2.11"] = "OIWSEC_rsaSign";
"1.3.14.3.2.12"] = "OIWSEC_dsa";
"1.3.14.3.2.13"] = "OIWSEC_shaDSA";
"1.3.14.3.2.14"] = "OIWSEC_mdc2RSA";
"1.3.14.3.2.15"] = "OIWSEC_shaRSA";
"1.3.14.3.2.16"] = "OIWSEC_dhCommMod";
"1.3.14.3.2.17"] = "OIWSEC_desEDE";
"1.3.14.3.2.18"] = "OIWSEC_sha";
"1.3.14.3.2.19"] = "OIWSEC_mdc2";
"1.3.14.3.2.20"] = "OIWSEC_dsaComm";
"1.3.14.3.2.21"] = "OIWSEC_dsaCommSHA";
"1.3.14.3.2.22"] = "OIWSEC_rsaXchg";
"1.3.14.3.2.23"] = "OIWSEC_keyHashSeal";
"1.3.14.3.2.24"] = "OIWSEC_md2RSASign";
"1.3.14.3.2.25"] = "OIWSEC_md5RSASign";
"1.3.14.3.2.26"] = "OIWSEC_sha1";
"1.3.14.3.2.27"] = "OIWSEC_dsaSHA1";
"1.3.14.3.2.28"] = "OIWSEC_dsaCommSHA1";
"1.3.14.3.2.29"] = "OIWSEC_sha1RSASign";
"1.3.14.7.2"] = "OIWDIR";
"1.3.14.7.2.1"] = "OIWDIR_CRPT";
"1.3.14.7.2.2"] = "OIWDIR_HASH";
"1.3.14.7.2.3"] = "OIWDIR_SIGN";
"1.3.14.7.2.2.1"] = "OIWDIR_md2";
"1.3.14.7.2.3.1"] = "OIWDIR_md2RSA";
"2.16.840.1.101.2.1"] = "INFOSEC";
"2.16.840.1.101.2.1.1.1"] =
                     "INFOSEC_sdnsSignature";
"2.16.840.1.101.2.1.1.2"] =
                   "INFOSEC_mosaicSignature";
"2.16.840.1.101.2.1.1.3"] =
                 "INFOSEC_sdnsConfidentiality";
"2.16.840.1.101.2.1.1.4"] =
               "INFOSEC_mosaicConfidentiality";
"2.16.840.1.101.2.1.1.5"] =
                "INFOSEC_sdnsIntegrity";
"2.16.840.1.101.2.1.1.6"] =
                "INFOSEC_mosaicIntegrity";
"2.16.840.1.101.2.1.1.7"] =
                "INFOSEC_sdnsTokenProtection";
"2.16.840.1.101.2.1.1.8"] =
           "INFOSEC_mosaicTokenProtection";
"2.16.840.1.101.2.1.1.9"] =
                  "INFOSEC_sdnsKeyManagement";
"2.16.840.1.101.2.1.1.10"] =
              "INFOSEC_mosaicKeyManagement";
"2.16.840.1.101.2.1.1.11"] =
              "INFOSEC_sdnsKMandSig";
"2.16.840.1.101.2.1.1.12"] =
                  "INFOSEC_mosaicKMandSig";
"2.16.840.1.101.2.1.1.13"] =
                  "INFOSEC_SuiteASignature";
"2.16.840.1.101.2.1.1.14"] =
               "INFOSEC_SuiteAConfidentiality";
"2.16.840.1.101.2.1.1.15"] =
               "INFOSEC_SuiteAIntegrity";
"2.16.840.1.101.2.1.1.16"] =
             "INFOSEC_SuiteATokenProtection";
"2.16.840.1.101.2.1.1.17"] =
                "INFOSEC_SuiteAKeyManagement";
"2.16.840.1.101.2.1.1.18"] =
                 "INFOSEC_SuiteAKMandSig";
"2.16.840.1.101.2.1.1.19"] =
                 "INFOSEC_mosaicUpdatedSig";
"2.16.840.1.101.2.1.1.20"] =
                  "INFOSEC_mosaicKMandUpdSig";
"2.16.840.1.101.2.1.1.21"] =
               "INFOSEC_mosaicUpdatedInteg";


*/
