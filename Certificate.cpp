// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "Certificate.h"
#include "CertExten.h"
#include "../CppBase/StIO.h"
#include "DerObjID.h"



// RFC 5280
// 4.1.  Basic Certificate Fields


Uint32 Certificate::parseOneCert(
                    const CharBuf& certBuf,
                    TlsMain& tlsMain )
{
StIO::putS( "\n\n\nParsing One Certificate." );

// Make sure this is reasonable.
// It should start with a Sequence tag.

Uint8 sequenceCheck = certBuf.getU8( 0 );
sequenceCheck = sequenceCheck & 0x1F;
if( sequenceCheck != DerEncode::SequenceTag )
  throw "parseOneCert() sequenceCheck bad.";

// For testing:
// DerEncodeLoop derEncodeLoop;
// derEncodeLoop.readAllTags( certBuf, 0,
//                            statusBuf, 0 );


// Test vector certificate is in RFC 8448:
// Example Handshake Traces for TLS 1.3

bool constructed = false;
DerEncode derEncode;
CharBuf statusBuf2;

CharBuf wholeCertBuf;

// There is one outer sequence tag that
// contains everything.

Int32 status = derEncode.readOneTag(
                              certBuf, 0,
                              constructed );

if( status < 0 )
  {
  throw "There is no certificate.";
  // StIO::putS( " error ..." );
  // return Alerts::BadCertificate;
  }

derEncode.getValue( wholeCertBuf );

// Get the three main Sequences in to
// these three buffers.

// tbsCertificate    To Be Signed.
CharBuf tbsCertBuf;

// signatureAlgorithm
CharBuf sigAlgBuf;

// signatureValue
CharBuf sigValBuf;

Int32 next = 0;

// tbsCertificate
next = derEncode.readOneTag( wholeCertBuf, next,
                             constructed );
if( next < 0 )
  {
  StIO::putS( "Certificate.cpp error 1." );
  return Alerts::BadCertificate;
  }

derEncode.getValue( tbsCertBuf );

// signatureAlgorithm
next = derEncode.readOneTag( wholeCertBuf,
                             next, constructed );

if( next < 0 )
  {
  StIO::putS( "Certificate.cpp error 2." );
  return Alerts::BadCertificate;
  }

derEncode.getValue( sigAlgBuf );

// signatureValue
next = derEncode.readOneTag( wholeCertBuf,
                             next, constructed );
if( next < 0 )
  {
  StIO::putS( "Certificate.cpp error 3." );
  return Alerts::BadCertificate;
  }

derEncode.getValue( sigValBuf );

Uint32 errorCode = parseTbsCert( tbsCertBuf,
                                 tlsMain );
if( errorCode != Results::Done )
  return errorCode;


// signatureAlgorithm
// sigAlgBuf
errorCode = parseAlgID( sigAlgBuf // , tlsMain
                        );
if( errorCode != Results::Done )
  return errorCode;


// signatureValue
// sigValBuf
// Just one BitStringTag.

// FileIO::writeAll( statusFileName, statusBuf );

return Results::Done;
}




Uint32 Certificate::parseTbsCert(
                    const CharBuf& certBuf,
                    TlsMain& tlsMain )
{
StIO::putS( "parseTbsCert() top." );
// Int32 certLast = certBuf.getLast();
// StIO::printF( "TBS certLast: " );
// StIO::printFD( certLast );
// StIO::putLF();

Int32 next = parseVersion( certBuf );
if( next < 1 )
  return Alerts::BadCertificate;

next = parseSerialNum( certBuf, next,
                                tlsMain );
if( next < 1 )
  return Alerts::BadCertificate;

next = parseTbsSigAlgID( certBuf, next // ,
                   // TlsMain& tlsMain
                   );

next = parseIssuer( certBuf, next // ,
                    // TlsMain& tlsMain
                    );

next = parseValidity( certBuf, next // ,
                       // TlsMain& tlsMain
                       );

next = parseSubject( certBuf,
                     next // ,
                     // TlsMain& tlsMain
                     );

next = parseSubjectPubKey( certBuf,
                           next,
                           tlsMain );

next = parseUniqueID( certBuf,
                      next );

if( next < 1 )
  return Results::Done;

// next =
parseExtensions( certBuf,
                 next // ,
                 // tlsMain
                 );


StIO::putS( "parseTbsCert() finished." );

return Results::Done;
}



Int32 Certificate::parseVersion(
                    const CharBuf& certBuf )
{
// RFC 5280 Section 4.1.2.1.  Version

// Have this return -1 on error.

// Since the Version is defined as EXPLICIT,
// it means it is wrapped in an outer encoding,
// which in this case is a tag with the
// ClassContextSpec bit set and the Constructed
// bit set.  And inside that
// is an INTEGER with the version in it.
// But the CertificateSerialNumber is just
// an INTEGER, it is IMPLICIT, and not
// wrapped in something else.

bool constructed = false;
DerEncode derEncode;

// This has the Context Specific class
// ClassContextSpec.

Int32 next = 0;
next = derEncode.readOneTag( certBuf,
                      next, constructed );

if( !constructed )
  throw
     "parseVersion() version not constructed.";

CharBuf contextSpecVal;
derEncode.getValue( contextSpecVal );

// Check that the three bytes are: 02 01 02
// Version is an Integer tag, length 1,
// version 3 is number 2.

// This only accepts version 3 certificates.

Int32 lastConSpec = contextSpecVal.getLast();
if( lastConSpec != 3 )
  throw "parseVersion() lastConSpec != 3.";

if( contextSpecVal.getU8( 0 ) !=
          DerEncode::IntegerTag )
  throw "parseVersion() version not Integer.";

// Length of 1.
if( contextSpecVal.getU8( 1 ) != 1 )
  throw "parseVersion() version bad length.";

// Number 2 is version 3.
if( contextSpecVal.getU8( 2 ) != 2 )
  throw "parseVersion() not version 3 cert.";

return next;
}



Int32 Certificate::parseSerialNum(
                    const CharBuf& certBuf,
                    const Int32 nextIn,
                    TlsMain& tlsMain )
{
// RFC 5280 Section 4.1.2.2.  Serial Number

bool constructed = false;
DerEncode derEncode;

Int32 next = derEncode.readOneTag( certBuf,
                      nextIn, constructed );

CharBuf serNumVal;
derEncode.getValue( serNumVal );
serialNum.setFromBigEndianCharBuf( serNumVal );

CharBuf showBuf;
tlsMain.intMath.toString10( serialNum,
                            showBuf );
StIO::putS( "Serial Number:" );
StIO::putCharBuf( showBuf );
StIO::putLF();

return next;
}




Int32 Certificate::parseTbsSigAlgID(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    )
{
// RFC 5280 Section 4.1.2.3.  Signature
// Algorithm ID for the Signature.

bool constructed = false;
DerEncode derEncode;

//  signature AlgorithmIdentifier,
// AlgorithmIdentifier  ::=  SEQUENCE
//  {
//  algorithm               OBJECT IDENTIFIER,
//  parameters              ANY DEFINED BY
//                  algorithm OPTIONAL
//  }

Int32 next = derEncode.readOneTag( certBuf,
                      nextIn, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "algID not a Sequence tag.";

CharBuf algIDSeq;
derEncode.getValue( algIDSeq );

// StIO::putS( "algIDSeq: " );
// algIDSeq.showHex();

Int32 nextInner = 0;
nextInner = derEncode.readOneTag( algIDSeq,
                  nextInner, constructed );

if( derEncode.getTag() !=
                   DerEncode::ObjectIDTag )
  throw "algID not an objectID tag.";

CharBuf algObjID;
derEncode.getValue( algObjID );

// StIO::putS( "algObjID: " );
// algObjID.showHex();

CharBuf algIDOut;
DerObjID::makeFromCharBuf( algObjID,
                           algIDOut );

StIO::putS( "algIDOut:" );
StIO::putCharBuf( algIDOut );
StIO::putLF();

// ======
// What I send in the handshake tells it
// what kind of certificates I can accept.

// 1.2.840.113549.1.1.1
// Defined in RFC 2313, 2437.
// See also RFC 3370.

// The test vectors have this for RSA:
// 1.2.840.113549.1.1.11
// PKCS 1:
// SHA256 with RSA encryption

// DurangoHerald.com goes through the
// security service at imperva.com for this:
// 1.2.840.10045.4.3.3
// ecdsa-with-SHA384(3)
// Elliptic curve Digital Signature Algorithm
// (DSA) coupled with the Secure Hash
// Algorithm 384 (SHA384) algorithm
// See RFC 5480 and RFC 5758.

// Parameters for the algID.

// nextInner =
derEncode.readOneTag( algIDSeq,
                 nextInner, constructed );

// It depends on the algorithm if
// there is a non null parameter.
// if( derEncode.getTag() !=
//                    DerEncode::NullTag )
  // throw "algID param not a NullTag.";

CharBuf algObjIDparams;
derEncode.getValue( algObjIDparams );
StIO::putS( "algObjIDparams: " );
if( algObjIDparams.getLast() == 0 )
  StIO::putS( "Zero length." );
else
  algObjIDparams.showHex();

return next;
}



Int32 Certificate::parseIssuer(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    )
{
// RFC 5280 Section 4.1.2.4.  Issuer.

StIO::putS( "parseIssuer top." );

bool constructed = false;
DerEncode derEncode;

Int32 next = derEncode.readOneTag( certBuf,
                  nextIn, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "issuer not a Sequence tag at 1.";

CharBuf seqOneVal;
derEncode.getValue( seqOneVal );

// next =
derEncode.readOneTag( seqOneVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SetTag )
  throw "issuer not a Set tag at 2.";

CharBuf setOneVal;
derEncode.getValue( setOneVal );

// next =
derEncode.readOneTag( setOneVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "issuer not a Sequence tag at 3.";

CharBuf seqTwoVal;
derEncode.getValue( seqTwoVal );


Int32 nextInner = derEncode.readOneTag(
                      seqTwoVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::ObjectIDTag )
  throw "issuerObjID not an objectID tag.";

CharBuf issuerObjIdVal;
derEncode.getValue( issuerObjIdVal );

CharBuf issuerIdOut;
DerObjID::makeFromCharBuf( issuerObjIdVal,
                           issuerIdOut );

// "2.5.4.3"] = "Common Name";

StIO::putS( "issuerIdOut:" );
StIO::putCharBuf( issuerIdOut );
StIO::putLF();

// PrintableStringTag
// Int32 nextInner =
derEncode.readOneTag( seqTwoVal,
                 nextInner, constructed );

if( derEncode.getTag() !=
              DerEncode::PrintableStringTag )
  throw "issuer is not a printableString.";

// teletexString, printableString,
// universalString, utf8String,
// bmpString.

// "CAs conforming to this profile MUST
// use either the PrintableString or
//   UTF8String encoding ..."
// Unless it uses some other obsolete type.


CharBuf issuerNameVal;
derEncode.getValue( issuerNameVal );
StIO::putS( "issuerNameVal:" );
StIO::putCharBuf( issuerNameVal );
StIO::putLF();

return next;
}




Int32 Certificate::parseValidity(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    )
{
// RFC 5280 Section 4.1.2.5.  Validity.

StIO::putS( "parseValidity top." );

bool constructed = false;
DerEncode derEncode;

// SequenceTag
// UTCTimeTag
// UTCTimeTag


Int32 next = derEncode.readOneTag( certBuf,
                      nextIn, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "Validity not a Sequence tag at 1.";

CharBuf seqVal;
derEncode.getValue( seqVal );

Int32 nextInner = derEncode.readOneTag(
                      seqVal,
                      0, constructed );

// CAs conforming to this profile MUST
// always encode certificate
// validity dates through the year
// 2049 as UTCTime; certificate validity
// dates in 2050 or later MUST be
// encoded as GeneralizedTime.

// Means no expiration:
// the GeneralizedTime value of
// 99991231235959Z.

// UTC Time has this form:
// YYMMDDHHMMSSZ


// Make it work with GeneralizedTime too.
if( derEncode.getTag() !=
                   DerEncode::UTCTimeTag )
  throw "Validity start not a UTCTime tag.";

CharBuf beginTimeVal;
derEncode.getValue( beginTimeVal );

StIO::putS( "beginTimeVal:" );
StIO::putCharBuf( beginTimeVal );
StIO::putLF();

// nextInner =
derEncode.readOneTag( seqVal,
                  nextInner, constructed );

if( derEncode.getTag() !=
                   DerEncode::UTCTimeTag )
  throw "Validity end not a UTCTime tag.";

CharBuf endTimeVal;
derEncode.getValue( endTimeVal );

StIO::putS( "endTimeVal:" );
StIO::putCharBuf( endTimeVal );
StIO::putLF();

return next;
}



Int32 Certificate::parseSubject(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    )
{
// RFC 5280 Section 4.1.2.6.  Subject.

// This is exactly like
// in parseIssuer().

StIO::putS( "parseSubject top." );

bool constructed = false;
DerEncode derEncode;


Int32 next = derEncode.readOneTag( certBuf,
                      nextIn, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "Subject not a Sequence tag at 1.";

CharBuf seqOneVal;
derEncode.getValue( seqOneVal );

// next =
derEncode.readOneTag( seqOneVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SetTag )
  throw "Subject not a Set tag at 2.";

CharBuf setOneVal;
derEncode.getValue( setOneVal );

// next =
derEncode.readOneTag( setOneVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "Subject not a Sequence tag at 3.";

CharBuf seqTwoVal;
derEncode.getValue( seqTwoVal );


Int32 nextInner = derEncode.readOneTag(
                      seqTwoVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::ObjectIDTag )
  throw "Subject ObjID not an objectID tag.";

CharBuf subjectObjIdVal;
derEncode.getValue( subjectObjIdVal );

CharBuf subjectIdOut;
DerObjID::makeFromCharBuf( subjectObjIdVal,
                           subjectIdOut );

// "2.5.4.3" = "Common Name";

StIO::putS( "subjectIdOut:" );
StIO::putCharBuf( subjectIdOut );
StIO::putLF();

// PrintableStringTag
// Int32 nextInner =
derEncode.readOneTag( seqTwoVal,
                 nextInner, constructed );

// if( derEncode.getTag() !=
//               DerEncode::PrintableStringTag )
//  throw "subject is not a printableString.";

// teletexString, printableString,
// universalString, utf8String,
// bmpString.

// "CAs conforming to this profile MUST
// use either the PrintableString or
//   UTF8String encoding ..."
// Unless it uses some other obsolete type.


CharBuf subjectNameVal;
derEncode.getValue( subjectNameVal );
StIO::putS( "subjectNameVal:" );
StIO::putCharBuf( subjectNameVal );
StIO::putLF();

return next;
}



Int32 Certificate::parseSubjectPubKey(
                    const CharBuf& certBuf,
                    const Int32 nextIn,
                    TlsMain& tlsMain )
{
// RFC 5280 Section 4.1.2.7.
// Subject Public Key Info

bool constructed = false;
DerEncode derEncode;

Int32 next = derEncode.readOneTag( certBuf,
                  nextIn, constructed );

if( next < 0 )
  {
  StIO::putS( "No Subject pub key data." );
  return -1;
  }

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw
     "SubjectPubKey not a Sequence tag at 1.";

CharBuf seqOneVal;
derEncode.getValue( seqOneVal );

Int32 nextSeq = derEncode.readOneTag(
                      seqOneVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw
    "SubjectPubKey not a Sequence tag at 2.";

CharBuf seqTwoVal;
derEncode.getValue( seqTwoVal );

Int32 nextInner = derEncode.readOneTag(
                      seqTwoVal,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::ObjectIDTag )
  throw "SubjectPubKey not an objectID tag.";

CharBuf algObjID;
derEncode.getValue( algObjID );

// StIO::putS( "algObjID: " );
// algObjID.showHex();

CharBuf algIDOut;
DerObjID::makeFromCharBuf( algObjID,
                           algIDOut );

StIO::putS( "algIDOut:" );
StIO::putCharBuf( algIDOut );
StIO::putLF();

// iso(1) member-body(2) us(840)
// rsadsi(113549) pkcs(1) pkcs-1(1)
//  sha256WithRSAEncryption(11)

// Test what kind of public keys this
// can process.

// It is this:
// "1.2.840.113549.1.1.1" =
//  "RSA_RSA RSA Encryption.
//  RFC 2313, 2437, 3370.";

// PKCS #1: RSA Encryption
// See RFC 8017.


// Parameters for the algID.

// nextInner =
derEncode.readOneTag( seqTwoVal,
                   nextInner, constructed );

// It depends on the algorithm if
// there is a non null parameter.
if( derEncode.getTag() !=
                   DerEncode::NullTag )
  throw
    "SubjectPubKey algID param not a NullTag.";

CharBuf algObjIDparams;
derEncode.getValue( algObjIDparams );
StIO::putS( "algObjIDparams: " );
if( algObjIDparams.getLast() == 0 )
  StIO::putS( "Zero length." );
else
  algObjIDparams.showHex();


// nextSeq =
derEncode.readOneTag( seqOneVal,
                      nextSeq, constructed );

if( derEncode.getTag() !=
                   DerEncode::BitStringTag )
  throw
    "SubjectPubKey BitStringTag not right.";

CharBuf pubKeyVal;
derEncode.getValue( pubKeyVal );
pubKeyNum.setFromBigEndianCharBuf( pubKeyVal );

CharBuf showBuf;
tlsMain.intMath.toString10( pubKeyNum,
                            showBuf );
StIO::putS( "Pub Key Number:" );
StIO::putCharBuf( showBuf );
StIO::putLF();

return next;
}



Int32 Certificate::parseUniqueID(
                    const CharBuf& certBuf,
                    const Int32 nextIn )
{
// RFC 5280 Section 4.1.2.8.
//  Unique Identifiers

if( nextIn < 0 )
  {
  StIO::putS( "No more data at UniqueID." );
  return -1;
  }

// "CAs conforming to this profile MUST
// NOT generate certificates with unique
// identifiers."

// ContextSpecific  and also BitStringTag.

Uint8 uniqueIDCheck = certBuf.getU8( nextIn );

if( (uniqueIDCheck &
         DerEncode::ClassContextSpec ) != 0 )
  {
  StIO::putS( "No UniqueID." );
  return nextIn;
  }

// 3 is BitStringTag but this is context
// specific.
uniqueIDCheck = uniqueIDCheck & 0x1F;
if( uniqueIDCheck != DerEncode::BitStringTag )
  throw "UniqueID has to be BitStringTag.";
  // return nextIn;

// UniqueIdentifier  ::=  BIT STRING

StIO::putS( "It has a UniqueIdentifier." );

bool constructed = false;
DerEncode derEncode;

Int32 next = derEncode.readOneTag( certBuf,
                      nextIn, constructed );

if( next < 0 )
  {
  StIO::putS( "Nothing at first UniqueID." );
  return -1;
  }


uniqueIDCheck = certBuf.getU8( next );

if( (uniqueIDCheck &
          DerEncode::ClassContextSpec ) != 0 )
  {
  uniqueIDCheck = uniqueIDCheck & 0x1F;
  if( uniqueIDCheck != DerEncode::BitStringTag )
    {
    StIO::putS( "No second UniqueID." );
    return next;
    }
  }

next = derEncode.readOneTag( certBuf,
                      next, constructed );

if( next < 0 )
  {
  StIO::putS( "Nothing after second UniqueID." );
  return -1;
  }

// Ignore those Unique IDs.

return next;
}



void Certificate::parseExtensions(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    )
{
// RFC 5280 Section 4.1.2.9.  Extensions

if( nextIn < 0 )
  {
  StIO::putS( "No extension data 1." );
  return;
  }


StIO::putS( "\n\n\nparseExtensions top." );

// Where is this wrapper in any RFC or
// specification?
// ContextSpecific and also BitStringTag.

// A wrapper around the extensions.
Uint8 extenWrapCheck = certBuf.getU8( nextIn );

if( (extenWrapCheck &
         DerEncode::ClassContextSpec ) == 0 )
  {
  throw "extenWrapCheck is bad 1.";
  // StIO::putS( "extenWrapCheck is bad." );
  // return -1;
  }

// 3 is BitStringTag but this is context
// specific.
extenWrapCheck = extenWrapCheck & 0x1F;
if( extenWrapCheck != DerEncode::BitStringTag )
  throw "extenWrapCheck has to be BitStringTag.";
  // return -1;

bool constructed = false;
DerEncode derEncode;

Int32 next = derEncode.readOneTag( certBuf,
                      nextIn, constructed );

if( next < 0 )
  {
  StIO::putS( "No extension data 2." );
  return;
  }

CharBuf extenWrapVal;
derEncode.getValue( extenWrapVal );

Int32 lastextenWrap = extenWrapVal.getLast();

// 26 bytes for the test vectors.
StIO::printF( "lastextenWrap: " );
StIO::printFD( lastextenWrap );
StIO::putLF();

// The outer sequence:
// Int32 next =
derEncode.readOneTag( extenWrapVal,
                      0, constructed );

CharBuf outerSeqVal;
derEncode.getValue( outerSeqVal );

Int32 lastouterSeq = outerSeqVal.getLast();

// 24 bytes for the test vectors.
StIO::printF( "lastouterSeq: " );
StIO::printFD( lastouterSeq );
StIO::putLF();

CertExten certExten;
Int32 nextExten = 0;
for( Int32 count = 0; count < 1000; count++ )
  {
  nextExten = derEncode.readOneTag(
                          outerSeqVal,
                    nextExten, constructed );

  if( nextExten < 0 )
    {
    StIO::putS( "No more extensions." );
    return;
    }

  if( derEncode.getTag() !=
                    DerEncode::SequenceTag )
    {
    StIO::putS( "Extension is not a Sequence." );
    return;
    }

  CharBuf oneExtenSeqVal;
  derEncode.getValue( oneExtenSeqVal );
  certExten.parseOneExten( oneExtenSeqVal );
  }

// Nothing comes after extensions.
}



Uint32 Certificate::parseAlgID(
                    const CharBuf& certBuf // ,
                    // TlsMain& tlsMain
                    )
{
StIO::putS( "parseAlgID() top." );

Int32 certLast = certBuf.getLast();
StIO::printF( "parseAlgID certLast: " );
StIO::printFD( certLast );
StIO::putLF();

//   AlgorithmIdentifier  ::=  SEQUENCE  {
//   algorithm               OBJECT IDENTIFIER,
//   parameters              ANY DEFINED
//                BY algorithm OPTIONAL  }

// Level: 1
// SequenceTag

// Level: 2
// ObjectIDTag

// Level: 2
// NullTag



StIO::putS( "parseAlgID() finished." );

return Results::Done;
}
