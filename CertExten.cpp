// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "CertExten.h"
#include "../CppBase/StIO.h"
#include "DerEncode.h"
#include "DerObjID.h"
#include "DerEncodeLoop.h"
#include "DerBitStr.h"


// RFC 5280 Section 4.1.2.9.  Extensions


/*
Level: 2
Class ContextSpec
Context Specific value: 3

// A Sequence that contains Sequences.


// One Extension:
//   SequenceTag
//     ObjectIDTag
//     Boolean Critical might or
//                 might not be here.
//     OctetStringTag
// This OctetString "contains the DER
// encoding of an ASN.1 value corresponding
// to the extension type identified
// by extnID."

Level: 3
SequenceTag

Level: 4
SequenceTag

Level: 5
ObjectIDTag

Level: 5
OctetStringTag

Level: 4
SequenceTag

Level: 5
ObjectIDTag

Level: 5
OctetStringTag


Extensions  ::=  SEQUENCE SIZE (1..MAX)
 OF Extension



Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
"The encoding of a set value or sequence
 value shall not include an encoding for
 any component value which is equal to
 its default value."
So Boolean false is not there in an extension.


     extnValue   OCTET STRING
          -- contains the DER encoding of
          an ASN.1 value
          -- corresponding to the extension
          type identified
          -- by extnID
     }
*/



void CertExten::parseOneExten( const CharBuf&
                            oneExtenSeqVal )
{
// StIO::putS( "\nparseOneExten top." );

// Int32 lastSeqVal = oneExtenSeqVal.getLast();
// StIO::printF( "lastSeqVal: " );
// StIO::printFD( lastSeqVal );
// StIO::putLF();

bool constructed = false;
DerEncode derEncode;
Int32 next = 0;
next = derEncode.readOneTag( oneExtenSeqVal,
                      next, constructed );

if( derEncode.getTag() !=
                   DerEncode::ObjectIDTag )
  throw "CertExten not an objectID tag.";

CharBuf objID;
derEncode.getValue( objID );

CharBuf objIDOut;
DerObjID::makeFromCharBuf( objID,
                           objIDOut );

StIO::putS( "objIDOut:" );
StIO::putCharBuf( objIDOut );
StIO::putLF();

bool critical = false;

Uint8 boolCheck = oneExtenSeqVal.getU8( next );
if( boolCheck == DerEncode::BooleanTag )
  {
  // StIO::putS( "Extension has a critical val." );

  // It is not supposed to be there if it
  // is the default value of false.
  // So just the fact that it is here means
  // it should be true.
  // critical    BOOLEAN DEFAULT FALSE,
  // value of false.  So if it's false it
  //_should_ be extnID followed by directly
  // by extnValue.
  // "The encoding of a set value or sequence
  // value shall not include an encoding for
  // any component value which is equal to
  // its default value."

  // In DER, the BOOLEAN type value true is:
  // 01 01 FF
  // True is any non zero value.
  // But for DER true can only be 0xFF.
  // But some non compliant things might
  // use any non zero value to mean true.

  next = derEncode.readOneTag(
                      oneExtenSeqVal,
                      next, constructed );

  CharBuf boolVal;
  derEncode.getValue( boolVal );
  // Int32 boolLen = boolVal.getLast();
  // StIO::printF( "Critical bool length: " );
  // StIO::printFD( boolLen );
  // StIO::putLF();
  Uint8 testBool = boolVal.getU8( 0 );
  if( testBool != 0 )
    critical = true;

  }

// Now get the buf data.
derEncode.readOneTag( oneExtenSeqVal,
                      next, constructed );

if( derEncode.getTag() !=
                   DerEncode::OctetStringTag )
  throw "CertExten data not Octet string.";

CharBuf octetString;
derEncode.getValue( octetString );
// StIO::printF( "OctetString: " );
// octetString.showHex();
// StIO::printF( "<There\n" );


if( objIDOut.isEqual( basicConstraintObjID ))
  {
  parseBasicConstraints( octetString,
                         critical );
  return;
  }

if( objIDOut.isEqual( keyUsageObjID ))
  {
  parseKeyUsage( octetString,
                 critical );
  return;
  }

if( objIDOut.isEqual( subjectKeyIDObjID ))
  {
  StIO::putS( "CertExten: subjectKeyIDObjID." );
  return;
  }

if( objIDOut.isEqual( subjectAltNameObjID ))
  {
  parseSubjectAltName( octetString, critical );
  return;
  }

if( objIDOut.isEqual( issuerAltNameObjID ))
  {
  parseIssuerAltName( octetString, critical );
  return;
  }

if( objIDOut.isEqual( crlDistribPtsObjID ))
  {
  StIO::putS( "CertExten: crlDistribPtsObjID." );
  return;
  }

if( objIDOut.isEqual( certPolicyObjID ))
  {
  StIO::putS( "CertExten: certPolicyObjID." );
  return;
  }

if( objIDOut.isEqual( authKeyIDObjID ))
  {
  StIO::putS( "CertExten: authKeyIDObjID." );
  return;
  }

if( objIDOut.isEqual( extenKeyUsageObjID ))
  {
  StIO::putS( "CertExten: extenKeyUsageObjID." );
  return;
  }

if( objIDOut.isEqual( authorityInfoAccessObjID ))
  {
  StIO::putS(
      "CertExten: authorityInfoAccessObjID." );
  return;
  }

StIO::putS( "CertExten: No matching extension." );
// throw "CertExten: No matching extension.";
}





void CertExten::parseBasicConstraints(
                    const CharBuf& octetString,
                    const bool critical )
{
// RFC 5280 Section 4.2.1.9.
// Basic Constraints

isACertAuthority = false;

StIO::putS( "Parsing Basic constraints." );

const Int32 last = octetString.getLast();
if( last < 1 )
  {
  StIO::putS( "Basic constraints: no data." );
  return;
  }

// RFC 5280 section 4.2.1.9.
//  Basic Constraints
// Object ID: 2.5.29.19

// "identifies whether the subject of the
//   certificate is a CA and the
//  maximum depth of valid certification
// paths"

// BasicConstraints ::= SEQUENCE {
// cA    BOOLEAN DEFAULT FALSE,
// pathLenConstraint INTEGER (0..MAX) OPTIONAL }

if( critical )
  {
  StIO::putS( "Basic constraints is critical." );
  }

DerEncode derEncode;
bool constructed = false;

derEncode.readOneTag( octetString,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "Basic Constraints not a Sequence tag.";

Uint32 seqLength = derEncode.getLength();
if( seqLength < 1 )
  {
  StIO::putS( "Basic constraints length 0." );
  // There is no path length for no CA.
  return;
  }

CharBuf seqData;
derEncode.getValue( seqData );
if( seqData.getLast() < 1 )
  return;

Int32 next = 0;
Uint8 boolCheck = seqData.getU8( next );
if( boolCheck == DerEncode::BooleanTag )
  {
  // If it's there at all it is true.
  // If it follows the specs.
  // isACertAuthority = true;

  next = derEncode.readOneTag(
                      seqData,
                      next, constructed );

  CharBuf boolVal;
  derEncode.getValue( boolVal );
  if( boolVal.getLast() < 1 )
    return;

  Uint8 testBool = boolVal.getU8( 0 );
  if( testBool != 0 )
    {
    // See below.
    isACertAuthority = true;
    StIO::putS( "Basic constraints: is a CA." );
    }
  else
    {
    StIO::putS(
           "Basic constraints: is not a CA." );

    // There is no path length for no CA.
    return;
    }
  }
else
  {
  // It doesn't have the bool tag.
  StIO::putS(
   "No bool tag. Basic constraints: not a CA." );

  // There is no path length for no CA.
  return;
  }

next = derEncode.readOneTag(
                      seqData,
                      next, constructed );

if( derEncode.getTag() !=
                   DerEncode::IntegerTag )
  throw "Basic Constraints not an Integer tag.";

Integer pathLength;

CharBuf numVal;
derEncode.getValue( numVal );
pathLength.setFromBigEndianCharBuf( numVal );

// This would be an Int32 because the path
// (number of certificates) can't be that long.

if( !pathLength.isLong48())
  throw "pathLength is not a long.";

// Int64 pathLen = pathLength.getAsLong48();
// StIO::printF( "Path length: " );
// StIO::printFD( pathLen );
// StIO::putLF();
}



void CertExten::parseKeyUsage(
                    const CharBuf& octetString,
                    const bool critical )
{
// RFC 5280 section 4.2.1.3.
// Key Usage

// Object ID: 2.5.29.15

StIO::putS( "Top of Basic key usage." );

if( critical )
  {
  StIO::putS( "Basic key usage is critical." );
  }

if( octetString.getLast() < 1 )
  {
  StIO::putS( "OctetString length is zero." );
  return;
  }

// 05 A0 means 5 unused bits on the right.
// A is 10, which is 1010.  Shifting right
// 5 bits is A0 >> 5 = 101.
// And it is Big Endian, so the bit on the
// right side is bit zero.

// So digitalSignature is set and
// keyEncipherment is set.

// digitalSignature        (0),
// nonRepudiation          (1),
//          -- recent editions of X.509 have
//          -- renamed this bit to
//             contentCommitment
// keyEncipherment         (2),
// dataEncipherment        (3),
// keyAgreement            (4),
// keyCertSign             (5),
// cRLSign                 (6),
// encipherOnly            (7),
// decipherOnly            (8) }

DerEncode derEncode;
bool constructed = false;
CharBuf statusBuf;

derEncode.readOneTag( octetString,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::BitStringTag )
  throw "Key Usage not a BitString tag.";

Uint32 bitArLength = derEncode.getLength();
if( bitArLength < 1 )
  {
  StIO::putS( "Key Usage length 0." );
  return;
  }

CharBuf bitStrData;
derEncode.getValue( bitStrData );
if( bitStrData.getLast() < 2 )
  throw "bitStrData length < 2";

// StIO::putS( "bitStrData:" );
// bitStrData.showHex();
// StIO::putLF();

DerBitStr derBitStr;
derBitStr.setCharBuf( bitStrData );

if( derBitStr.getBitAt( 0 ))
  StIO::putS( "digitalSignature bit is set." );

if( derBitStr.getBitAt( 2 ))
  StIO::putS( "keyEncipherment bit is set." );

}



void CertExten::parseSubjectAltName(
                    const CharBuf& octetString,
                    const bool critical )
{
// RFC 5280 Section 4.2.1.6.
//  Subject Alternative Name

StIO::putS( "\n\n\n=============" );

StIO::putS( "Top of Subject Alt Name" );

const Int32 last = octetString.getLast();
if( last < 1 )
  {
  StIO::putS( "SubjectAltName: no data." );
  return;
  }

if( critical )
  {
  StIO::putS( "SubjectAltName is critical." );
  }

DerEncode derEncode;
bool constructed = false;
CharBuf statusBuf;

// This is the one big outer sequence.
derEncode.readOneTag( octetString,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "SubjectAltName not a Sequence tag.";

Uint32 seqLength = derEncode.getLength();
if( seqLength < 1 )
  {
  StIO::putS( "SubjectAltName seqLength 0." );
  return;
  }

CharBuf seqData;
derEncode.getValue( seqData );

// This is something like 1,982 bytes.
const Int32 seqDataLast = seqData.getLast();


StIO::printF( "seqDataLast: " );
StIO::printFD( seqDataLast );
StIO::putLF();

Int32 next = 0;

// How many of these does it have?
for( Int32 count = 0; count < 1000; count++ )
  {
  // StIO::putLF();

  next = derEncode.readOneTag( seqData,
                      next, constructed );

  if( next < 1 )
    {
    StIO::putS( "No more contextSpec tags." );
    break;
    }

  if( !derEncode.getIsContextSpec())
    throw "CertExten tag should be contextSpec.";

  CharBuf nameVal;
  derEncode.getValue( nameVal );

  nameVal.showAscii();
  }



/*
// EnumeratedTag = 10;
0A 01 01
0A is the Enumerated tag. 01 is the length?
and 01 is the enumerated value.

So get an enumerated value:
        otherName                 [0]     OtherName,
        rfc822Name                [1]     IA5String,
        dNSName                   [2]     IA5String,
        x400Address               [3]     ORAddress,
        directoryName             [4]     Name,
        ediPartyName              [5]     EDIPartyName,
        uniformResourceIdentifier [6]     IA5String,
        iPAddress                 [7]     OCTET STRING,
        registeredID              [8]     OBJECT IDENTIFIER }



   SubjectAltName ::= GeneralNames

   GeneralNames ::=
SEQUENCE SIZE (1..MAX) OF GeneralName

   GeneralName ::= CHOICE {
        otherName                 [0]     OtherName,
        rfc822Name                [1]     IA5String,
        dNSName                   [2]     IA5String,
        x400Address               [3]     ORAddress,
        directoryName             [4]     Name,
        ediPartyName              [5]     EDIPartyName,
        uniformResourceIdentifier [6]     IA5String,
        iPAddress                 [7]     OCTET STRING,
        registeredID              [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED
                    BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }

*/


StIO::putS( "=============\n\n\n" );
}



void CertExten::parseIssuerAltName(
                    const CharBuf& octetString,
                    const bool critical )
{
// RFC 5280 Section 4.2.1.7.
//  Issuer Alternative Name

StIO::putS( "\n\n\n=============" );

StIO::putS( "Top of Issuer Alt Name" );

const Int32 last = octetString.getLast();
if( last < 1 )
  {
  StIO::putS( "IssuerAltName: no data." );
  return;
  }

if( critical )
  {
  StIO::putS( "IssuerAltName is critical." );
  }

DerEncode derEncode;
bool constructed = false;
CharBuf statusBuf;

// This is the one big outer sequence.
derEncode.readOneTag( octetString,
                      0, constructed );

if( derEncode.getTag() !=
                   DerEncode::SequenceTag )
  throw "IssuerAltName not a Sequence tag.";

Uint32 seqLength = derEncode.getLength();
if( seqLength < 1 )
  {
  StIO::putS( "IssuerAltName seqLength 0." );
  return;
  }

CharBuf seqData;
derEncode.getValue( seqData );

const Int32 seqDataLast = seqData.getLast();


StIO::printF( "seqDataLast: " );
StIO::printFD( seqDataLast );
StIO::putLF();

Int32 next = 0;

// How many of these does it have?
for( Int32 count = 0; count < 1000; count++ )
  {
  // StIO::putLF();

  next = derEncode.readOneTag( seqData,
                      next, constructed );

  if( next < 1 )
    {
    StIO::putS( "No more contextSpec tags." );
    break;
    }

  if( !derEncode.getIsContextSpec())
    throw "CertExten tag should be contextSpec.";

  CharBuf nameVal;
  derEncode.getValue( nameVal );

  nameVal.showAscii();
  }

StIO::putS( "=============\n\n\n" );
}
