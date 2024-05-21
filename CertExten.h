// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// See https://ericssourcecode.github.io/
// For guides and information.


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "DerEncode.h"
#include "../Network/Alerts.h"
#include "../Network/Results.h"
#include "../CppBase/FileIO.h"
#include "../Network/TlsMain.h"


// RFC 5280 is the main one.
// Section 4.2.  Certificate Extensions


/*
RFC 5280 Section 4.2.

4.2. Certificate Extensions
4.2.1. Standard Extensions
4.2.1.1. Authority Key Identifier
4.2.1.2. Subject Key Identifier
4.2.1.3. Key Usage
4.2.1.4. Certificate Policies
4.2.1.5. Policy Mappings
4.2.1.6. Subject Alternative Name
4.2.1.7. Issuer Alternative Name
4.2.1.8. Subject Directory Attributes
4.2.1.9. Basic Constraints
4.2.1.10. Name Constraints
4.2.1.11. Policy Constraints
4.2.1.12. Extended Key Usage
4.2.1.13. CRL Distribution Points
4.2.1.14. Inhibit anyPolicy
4.2.1.15. Freshest CRL (a.k.a. Delta CRL
  Distribution Point)
4.2.2. Private Internet Extensions


           4.2.2. Private Internet Extensions ........................49
                  4.2.2.1. Authority Information Access ..............49
                  4.2.2.2. Subject Information Access ................51

1.3.6.1.5.5.7.1.1
4.2.2.1. Authority Information Access

RFC 6962
Certificate Transparency
1.3.6.1.4.1.11129.2.4.2
Extended Validation Certificates


4.2.2.2. Subject Information Access


Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
     extnValue   OCTET STRING
          -- contains the DER encoding of
          an ASN.1 value
          -- corresponding to the extension
          type identified
          -- by extnID
     }

*/



class CertExten
  {
  private:
  bool testForCopy = false;

  CharBuf subjectKeyIDObjID;
  CharBuf keyUsageObjID;
  CharBuf subjectAltNameObjID;
  CharBuf issuerAltNameObjID;
  CharBuf basicConstraintObjID;
  CharBuf crlDistribPtsObjID;
  CharBuf certPolicyObjID;
  CharBuf authKeyIDObjID;
  CharBuf extenKeyUsageObjID;
  CharBuf authorityInfoAccessObjID;
  CharBuf subjectInfoAccessObjID;
  CharBuf certTransparencyObjID;
  bool isACertAuthority = false;

  public:
  CertExten( void )
    {
    subjectKeyIDObjID.setFromCharPoint(
                         "2.5.29.14" );

    keyUsageObjID.setFromCharPoint(
                         "2.5.29.15" );

    // Subject Alternative Name
    subjectAltNameObjID.setFromCharPoint(
                         "2.5.29.17" );

    // Issuer Alternative Name
    issuerAltNameObjID.setFromCharPoint(
                         "2.5.29.18" );

    basicConstraintObjID.setFromCharPoint(
                         "2.5.29.19" );

    // CRL Distribution Points
    crlDistribPtsObjID.setFromCharPoint(
                         "2.5.29.31" );

    // Certificate Policies
    certPolicyObjID.setFromCharPoint(
                         "2.5.29.32" );

    // Authority Key Identifier
    authKeyIDObjID.setFromCharPoint(
                         "2.5.29.35" );

    // Extended key usage
    extenKeyUsageObjID.setFromCharPoint(
                         "2.5.29.37" );

    authorityInfoAccessObjID.setFromCharPoint(
                    "1.3.6.1.5.5.7.1.1" );

    // subjectInfoAccessObjID

    certTransparencyObjID.setFromCharPoint(
       "1.3.6.1.4.1.11129.2.4.2" );


    }

  CertExten( const CertExten& in )
    {
    if( in.testForCopy )
      return;

    throw "CertExten copy constructor.";
    }

  ~CertExten( void )
    {
    }

  void parseOneExten(
                const CharBuf& oneExtenSeqVal );

  void parseBasicConstraints(
                    const CharBuf& extenData,
                    const bool critical );

  void parseKeyUsage(
                 const CharBuf& octetString,
                 const bool critical );

  void parseSubjectAltName(
                 const CharBuf& octetString,
                 const bool critical );

  void parseIssuerAltName(
                 const CharBuf& octetString,
                 const bool critical );

  void parseSubjectKeyID(
                   const CharBuf& octetString,
                   const bool critical );

  void parseCrlDistribPts(
                    const CharBuf& octetString,
                    const bool critical );

  };
