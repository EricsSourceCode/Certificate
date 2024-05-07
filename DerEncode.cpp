// Copyright Eric Chauvin 2023 - 2024.




// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#include "DerEncode.h"
#include "../CppBase/StIO.h"


void DerEncode::getValue( CharBuf& val ) const
{
val.copy( value );
}



Int32 DerEncode::readOneTag(
                    const CharBuf& cBuf,
                    const Int32 where,
                    bool& constructed )
{
tag = 0;
length = 0;
value.clear();

if( where < 0 )
  throw "DerEncode where is < 0.";

const Int32 lastCBuf = cBuf.getLast();
if( where >= lastCBuf )
  {
  // StIO::putS( "No more tags to read." );
  return -1;
  }

// See CertTag.h for how these values are
// read from the file.

Int32 index = where;
Uint8 aByte = cBuf.getU8( index );

constructed = false;
if( (aByte & ConstructedBit) != 0 )// 0x20;
  constructed = true;


Uint8 fullTagByte = aByte;

// Get rid of class bits and constructed bit.
aByte = aByte & 0x1F;

// LongFormBits = 0x1F;

if( aByte < LongFormBits )
  {
  // StIO::putS( "Tag is short form." );
  tag = aByte;
  }
else
  {
  if( aByte != LongFormBits )
    throw "All long form bits should be set.";

  // StIO::putS( "Tag is long form." );
  index++;
  aByte = cBuf.getU8( index );

  // This doesn't handle longer tags.
  if( (aByte & 0x80) != 0 )
    throw "DerEncode tag is too long.";

  tag = aByte; //  & 0x7F;
  }

// StIO::putLF();

if( (tag >> 16) != 0 )
  throw "DerEncode tag too big.";

// u16Buf.appendU16( tag & 0xFFFF );

// showTag( fullTagByte, tag, statusBuf );

if( (fullTagByte & ClassContextSpec ) != 0 )
  isContextSpec = true;
else
  isContextSpec = false;



// For DER the length can only be in
// Definite Form.

index++;
aByte = cBuf.getU8( index );
if( (aByte & 0x80) == 0 )
  {
  // StIO::putS( "Length is short form." );
  length = aByte;
  index++;
  }
else
  {
  // StIO::putS( "Length is long form." );

  if( aByte == 0x80 )
    throw "DER length can not be indefinite.";


  // Long form.
  Uint32 octets = aByte & 0x7F;
  index++;

  // StIO::printF( "Length octets: " );
  // StIO::printFUD( octets );
  // StIO::putLF();

  // Check if it is a reasonable length
  // for one tag in a Certificate.
  if( octets > 4 )
    throw "DerEncode length too many octets.";

  length = 0;
  if( octets == 4 )
    {
    aByte = cBuf.getU8( index );
    length = aByte;
    length <<= 8;
    index++;

    aByte = cBuf.getU8( index );
    length |= aByte;
    length <<= 8;
    index++;

    aByte = cBuf.getU8( index );
    length |= aByte;
    length <<= 8;
    index++;

    aByte = cBuf.getU8( index );
    length |= aByte;
    index++;
    }

  if( octets == 3 )
    {
    aByte = cBuf.getU8( index );
    length = aByte;
    length <<= 8;
    index++;

    aByte = cBuf.getU8( index );
    length |= aByte;
    length <<= 8;
    index++;

    aByte = cBuf.getU8( index );
    length |= aByte;
    index++;
    }

  if( octets == 2 )
    {
    aByte = cBuf.getU8( index );
    length = aByte;
    length <<= 8;
    index++;

    aByte = cBuf.getU8( index );
    length |= aByte;
    index++;
    }

  if( octets == 1 )
    {
    // It's one octet but it is all 8 bits.
    aByte = cBuf.getU8( index );
    length = aByte;
    index++;
    }
  }

// StIO::printF( "Length: " );
// StIO::printFUD( length );
// StIO::putLF();

// Big endian.
// u16Buf.appendU16( (length >> 16) & 0xFFFF );
// u16Buf.appendU16( length & 0xFFFF );

for( Uint32 count = 0; count < length; count++ )
  {
  if( index >= lastCBuf )
    throw "DerEncode index >= lastCBuf.";

  aByte = cBuf.getU8( index );
  value.appendU8( aByte );

  // This byte size value won't interfere
  // the the delimiters.
  // u16Buf.appendU16( aByte );

  // if( (aByte >= 32) && (aByte < 127) )
    // StIO::putChar( aByte );

  index++;
  }

// u16Buf.appendU16( TagEndDelim );

// StIO::putLF();

// Just past where it last read a byte.
return index;
}



void DerEncode::showTag( Uint32 fullTagByte,
                         Uint32 tagByte,
                         CharBuf& statusBuf )
{
// if( (fullTagByte >> 6) == 0 )
  // statusBuf.appendCharPt(
      //        "Class Universal\n" );

if( (fullTagByte & ClassApplication ) != 0 )
  statusBuf.appendCharPt(
                "Class Application\n" );

if( (fullTagByte & ClassContextSpec ) != 0 )
  {
  isContextSpec = true;
  statusBuf.appendCharPt(
                  "Class ContextSpec\n" );
  }
else
  {
  isContextSpec = false;
  }

if( (fullTagByte & ClassPrivate) ==
                              ClassPrivate )
  statusBuf.appendCharPt( "Class Private\n" );

// It can be constructed of multiple tags.
// If it is not Constucted then it is Primitive
// and it has only the one value in it.
// Things can have zero values in them.

// if( (fullTagByte & ConstructedBit) != 0 )
  // statusBuf.appendCharPt(
  //          "Constructed Bit\n" );

if( (fullTagByte & ClassContextSpec ) != 0 )
  {
  statusBuf.appendCharPt(
              "Context Specific value: " );
  CharBuf numberBuf( tagByte );
  statusBuf.appendCharBuf( numberBuf );
  statusBuf.appendCharPt( "\n" );

  return;
  }

Uint32 showIt = tagByte;
if( showIt == EndOfContentTag )
  {
  statusBuf.appendCharPt( "EndOfContentTag\n" );
  return;
  }

if( showIt == BooleanTag )
  {
  statusBuf.appendCharPt( "BooleanTag\n" );
  return;
  }

if( showIt == IntegerTag )
  {
  statusBuf.appendCharPt( "IntegerTag\n" );
  return;
  }

if( showIt == BitStringTag )
  {
  statusBuf.appendCharPt( "BitStringTag\n" );
  return;
  }

if( showIt == OctetStringTag )
  {
  statusBuf.appendCharPt( "OctetStringTag\n" );
  return;
  }

if( showIt == NullTag )
  {
  statusBuf.appendCharPt( "NullTag\n" );
  return;
  }

if( showIt == ObjectIDTag )
  {
  statusBuf.appendCharPt( "ObjectIDTag\n" );
  return;
  }

if( showIt == ObjectDescripTag )
  {
  statusBuf.appendCharPt( "ObjectDescripTag\n" );
  return;
  }

if( showIt == ExternalTag )
  {
  statusBuf.appendCharPt( "ExternalTag\n" );
  return;
  }

if( showIt == RealFloatTag )
  {
  statusBuf.appendCharPt( "RealFloatTag\n" );
  return;
  }

if( showIt == EnumeratedTag )
  {
  statusBuf.appendCharPt( "EnumeratedTag\n" );
  return;
  }

if( showIt == EmbeddedPdvTag )
  {
  statusBuf.appendCharPt( "EmbeddedPdvTag\n" );
  return;
  }

if( showIt == UTF8StringTag )
  {
  statusBuf.appendCharPt( "UTF8StringTag\n" );
  return;
  }

if( showIt == RelativeOIDTag )
  {
  statusBuf.appendCharPt( "RelativeOIDTag\n" );
  return;
  }

if( showIt == TimeTag )
  {
  statusBuf.appendCharPt( "TimeTag\n" );
  return;
  }

if( showIt == SequenceTag )
  {
  statusBuf.appendCharPt( "SequenceTag\n" );
  return;
  }

if( showIt == SetTag )
  {
  statusBuf.appendCharPt( "SetTag\n" );
  return;
  }

if( showIt == NumericStringTag )
  {
  statusBuf.appendCharPt( "NumericStringTag\n" );
  return;
  }

if( showIt == PrintableStringTag )
  {
  statusBuf.appendCharPt(
                   "PrintableStringTag\n" );
  return;
  }

if( showIt == T61StringTag )
  {
  statusBuf.appendCharPt( "T61StringTag\n" );
  return;
  }

if( showIt == VideoTexStringTag )
  {
  statusBuf.appendCharPt(
                    "VideoTexStringTag\n" );
  return;
  }

if( showIt == IA5StringTag )
  {
  statusBuf.appendCharPt( "IA5StringTag\n" );
  return;
  }

if( showIt == UTCTimeTag )
  {
  statusBuf.appendCharPt( "UTCTimeTag\n" );
  return;
  }

if( showIt == GeneralizedTimeTag )
  {
  statusBuf.appendCharPt(
                     "GeneralizedTimeTag\n" );
  return;
  }

if( showIt == GraphicStringTag )
  {
  statusBuf.appendCharPt( "GraphicStringTag\n" );
  return;
  }

if( showIt == VisibleStringTag )
  {
  statusBuf.appendCharPt( "VisibleStringTag\n" );
  return;
  }

if( showIt == GeneralStringTag )
  {
  statusBuf.appendCharPt( "GeneralStringTag\n" );
  return;
  }

if( showIt == UniversalStringTag )
  {
  statusBuf.appendCharPt(
                    "UniversalStringTag\n" );
  return;
  }

if( showIt == CharacterStringTag )
  {
  statusBuf.appendCharPt(
                    "CharacterStringTag\n" );
  return;
  }

if( showIt == BMPStringTag )
  {
  statusBuf.appendCharPt( "BMPStringTag\n" );
  return;
  }

if( showIt == DateTag )
  {
  statusBuf.appendCharPt( "DateTag\n" );
  return;
  }

if( showIt == TimeOfDayTag )
  {
  statusBuf.appendCharPt( "TimeOfDayTag\n" );
  return;
  }

if( showIt == DateTimeTag )
  {
  statusBuf.appendCharPt( "DateTimeTag\n" );
  return;
  }

if( showIt == DurationTag )
  {
  statusBuf.appendCharPt( "DurationTag\n" );
  return;
  }

if( showIt == OidIriTag )
  {
  statusBuf.appendCharPt( "OidIriTag\n" );
  return;
  }

if( showIt == RelativeOidIriTag )
  {
  statusBuf.appendCharPt(
                     "RelativeOidIriTag\n" );
  return;
  }

statusBuf.appendCharPt(
                "showTag() Unknown Tag\n" );

}
