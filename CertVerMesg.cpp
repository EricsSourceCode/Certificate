// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "CertVerMesg.h"
#include "../CppBase/StIO.h"



Uint32 CertVerMesg::parseCertVerMsg(
                    const CharBuf& certVerBuf,
                    TlsMain& tlsMain )
{
StIO::putS(
      "Parsing Certificate Verify Message." );

tlsMain.setCertVerifyMsg( certVerBuf );

// StIO::putLF();
// certVerBuf.showHex();
// StIO::putLF();



/*

const Int32 last = certBuf.getLast();
StIO::printF( "certBuf last: " );
StIO::printFD( last );
StIO::putLF();

if( last < 4 )
  {
  StIO::putS(
      "parseCertMsg: certBuf last < 4." );

  return Results::Done;
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

Uint32 certListLength = certBuf.getU8( 1 );
certListLength <<= 8;
certListLength |= certBuf.getU8( 2 );
certListLength <<= 8;
certListLength |= certBuf.getU8( 3 );

StIO::printF( "certListLength: " );
StIO::printFUD( certListLength );
StIO::putLF();

Int32 index = 4;

if( (index + 3) >= last )
  {
  StIO::putS( "Nothing left in certBuf." );
  return Results::Done;
  }

Uint32 certLength = certBuf.getU8( index );
index++;
certLength <<= 8;
certLength |= certBuf.getU8( index );
index++;
certLength <<= 8;
certLength |= certBuf.getU8( index );
index++;

// if( certLength == 0 )

StIO::printF( "certLength: " );
StIO::printFUD( certLength );
StIO::putLF();

CharBuf oneCertBuf;

for( Uint32 count = 0; count < certLength;
                                count++ )
  {
  oneCertBuf.appendU8(
                    certBuf.getU8( index ));
  index++;
  }

Certificate cert;

// if result is an alert...

Uint32 result = cert.parseOneCert(
                            oneCertBuf,
                            tlsMain );

if( result != Results::Done )
  {
  StIO::putS( "cert.parseOneCert was bad." );
  return result;
  }


if( (index + 3) >= last )
  {
  StIO::putS( "Nothing left in certBuf." );
  return Results::Done;
  }

certLength = certBuf.getU8( index );
index++;
certLength <<= 8;
certLength |= certBuf.getU8( index );
index++;
certLength <<= 8;
certLength |= certBuf.getU8( index );
index++;

// if( certLength == 0 )

StIO::printF( "certLength: " );
StIO::printFUD( certLength );
StIO::putLF();

if( (index + 3) >= last )
  {
  StIO::putS( "Nothing left in certBuf." );
  return Results::Done;
  }

// Why is this derLength two bytes?
Uint32 derLength = certBuf.getU8( index );
index++;
derLength <<= 8;
derLength |= certBuf.getU8( index );
index++;

StIO::printF( "derLength: " );
StIO::printFUD( derLength );
StIO::putLF();


oneCertBuf.clear();
for( Uint32 count = 0; count < derLength;
                                count++ )
  {
  oneCertBuf.appendU8(
                    certBuf.getU8( index ));
  index++;
  }


// result =
cert.parseOneCert( oneCertBuf, tlsMain );

// if( result != Results::Done )



// CharBuf showDerBuf;
// For testing:
// DerEncodeLoop derEncodeLoop;
// derEncodeLoop.readAllTags( certBuf, index,
//                           showDerBuf, 0 );

// const char* certStatusFileName =
// "\\Eric\\main\\TlsClient\\CertExtenStatus.txt";

// FileIO::writeAll( certStatusFileName,
//                   showDerBuf );



//////////
CharBuf showBytes;
Int32 howMany = 0;
for( Int32 count = 0; count < 1000000; count++ )
  {
  if( index >= last )
    break;

  showBytes.appendU8( certBuf.getU8( index ));

  Uint8 sequenceCheck = certBuf.getU8( index );
  sequenceCheck = sequenceCheck & 0x1F;
  if( sequenceCheck == DerEncode::SequenceTag )
    {
    StIO::putLF();
    StIO::printF( "howMany: " );
    StIO::printFD( howMany );
    StIO::putLF();
    // break;
    }

  howMany++;
  index++;
  }

StIO::putLF();
StIO::putS( "showBytes: " );

showBytes.showHex();

StIO::putLF();
/////////


*/


StIO::putLF();
StIO::putS( "End of Cert Verify Message." );

return Results::Done;
}
