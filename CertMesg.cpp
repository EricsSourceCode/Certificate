// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "CertMesg.h"
#include "Certificate.h"
#include "../CppBase/StIO.h"



Uint32 CertMesg::parseCertMsg(
                    const CharBuf& certBuf,
                    TlsMain& tlsMain )
{
StIO::putS( "Parsing Certificate Message." );

// The certificate message is in RFC 8446
// section-4.4.2.

// Certificate type:
//        X509(0),
//        RawPublicKey(2),


const Int32 last = certBuf.getLast();

if( last < 4 )
  {
  throw "parseCertMsg: certBuf last < 4.";
  // return Results:: something.
  }

Uint8 certType = certBuf.getU8( 0 );

// RFC 7250 Raw Public Keys

// Can't deal with Raw Public Key yet.
if( certType != 0 )
  throw "Certificate type is not X509.";

// "in the case of server authentication,
// this field SHALL be zero length."

// This is not there if the server is sending
// this message.
// Uint8 certRequestContext = certBuf.getU8( 1 );

Int32 certListLength = certBuf.getU8( 1 );
certListLength <<= 8;
certListLength |= certBuf.getU8( 2 );
certListLength <<= 8;
certListLength |= certBuf.getU8( 3 );

// StIO::printF( "certListLength: " );
// StIO::printFUD( certListLength );
// StIO::putLF();

Int32 index = 4;

if( (index + 3) >= last )
  {
  throw "Nothing in certBuf.";
  // return Results::  something;
  }

// This loop is for the chain of certificates.
// There can't be a hundred of them.

for( Int32 certCount = 0; certCount < 100;
                            certCount++ )
  {
  // One certificate's length.
  Uint32 certLength = certBuf.getU8( index );
  index++;
  certLength <<= 8;
  certLength |= certBuf.getU8( index );
  index++;
  certLength <<= 8;
  certLength |= certBuf.getU8( index );
  index++;

  // if( certLength == 0 )
  // Or if it is too big...
  // Or something...

  // StIO::printF( "certLength: " );
  // StIO::printFUD( certLength );
  // StIO::putLF();

  CharBuf oneCertBuf;

  for( Uint32 count = 0; count < certLength;
                                count++ )
    {
    oneCertBuf.appendU8(
                    certBuf.getU8( index ));
    index++;
    }

  Certificate cert;

  Uint32 result = cert.parseOneCert(
                            oneCertBuf,
                            tlsMain );

  if( result != Results::Done )
    {
    throw "cert.parseOneCert was bad.";
    // return result;
    }

  if( (index + 3) >= last )
    {
    StIO::putS(
          "Nothing left in certBuf.\n\n\n" );
    return Results::Done;
    }

  // The extensions that come after a
  // certificate.
  // Two bytes for the length.
  Uint32 extenLength = certBuf.getU8( index );
  index++;
  extenLength <<= 8;
  extenLength |= certBuf.getU8( index );
  index++;

  // StIO::printF( "extenLength: " );
  // StIO::printFUD( extenLength );
  // StIO::putLF();

  // Do something with these extensions.
  if( extenLength != 0 )
    throw "CertMesg extenLength != 0";

  if( index >= certListLength )
    {
    StIO::putS( "index >= certListLength" );
    break;
    }


  // RFC 8446 Section 4.2 for regular
  // extensions is in ExtenList.cpp.

  // From the RFC:
  // "extensions:  A set of extension values
  // for the CertificateEntry.  The
  // Extension format is defined in
  // Section 4.2.  Valid extensions
  // for server certificates at present
  // include the OCSP Status
  // extension
  // Transport Layer Security (TLS) Extensions:
  // Extension Definitions RFC6066] and the
  // SignedCertificateTimestamp
  // extension
  // [Certificate Transparency RFC 6962];
  }

StIO::putS(
   "\nCertMesg: It should never get here.\n" );

return Results::Done;
}
