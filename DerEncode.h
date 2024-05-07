// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppBase/Uint16Buf.h"
#include "../CppBase/Markers.h"
#include "../CppInt/IntegerMath.h"



// DER: Distinguished Encoding Rules.
// The X.690 standard is DER Encoding.



class DerEncode
  {
  private:
  bool testForCopy = false;
  Uint32 tag = 0;
  Uint32 length = 0;
  CharBuf value;
  bool isContextSpec = false;

  public:
  static const Uint16 LevelDelim =
                             Markers::First;
  static const Uint16 TagStartDelim =
                          Markers::First + 1;
  static const Uint16 TagEndDelim =
                          Markers::First + 2;


  static const Uint8 LongFormBits = 0x1F;

  static const Uint8 ConstructedBit = 0x20;

  // Class bits:
  static const Uint8 ClassUniversal = 0x00;
  static const Uint8 ClassApplication = 0x40;
  static const Uint8 ClassContextSpec = 0x80;
  static const Uint8 ClassPrivate = 0xC0;

  static const Uint8 EndOfContentTag = 0;
  static const Uint8 BooleanTag = 1;
  static const Uint8 IntegerTag = 2;
  static const Uint8 BitStringTag = 3;
  static const Uint8 OctetStringTag = 4;
  static const Uint8 NullTag = 5;
  static const Uint8 ObjectIDTag = 6;
  static const Uint8 ObjectDescripTag = 7;
  static const Uint8 ExternalTag = 8;
  static const Uint8 RealFloatTag = 9;
  static const Uint8 EnumeratedTag = 10;
  static const Uint8 EmbeddedPdvTag = 11;
  static const Uint8 UTF8StringTag = 12;
  static const Uint8 RelativeOIDTag = 13;
  static const Uint8 TimeTag = 14;

  // SequenceOfTag is 0x10 too.
  static const Uint8 SequenceTag = 0x10; // 16
  static const Uint8 SequenceOfTag = 0x10;

  static const Uint8 SetTag = 0x11; // 17
  static const Uint8 SetOfTag = 0x11;

  static const Uint8 NumericStringTag = 18;
  static const Uint8 PrintableStringTag = 19;
  static const Uint8 T61StringTag = 20;
  static const Uint8 VideoTexStringTag = 21;
  static const Uint8 IA5StringTag = 22;
  static const Uint8 UTCTimeTag = 23;
  static const Uint8 GeneralizedTimeTag = 24;
  static const Uint8 GraphicStringTag = 25;
  static const Uint8 VisibleStringTag = 26;
  static const Uint8 GeneralStringTag = 27;
  static const Uint8 UniversalStringTag = 28;
  static const Uint8 CharacterStringTag = 29;
  static const Uint8 BMPStringTag = 30;

  // Tag types over 30 are long form tags.
  // LongFormBits = 0x1F;

  // Date is equal to LongFormBits
  // Date is in long form.

  static const Uint8 DateTag = 31; // 0x1F
  static const Uint8 TimeOfDayTag = 32; // 0x20
  static const Uint8 DateTimeTag = 33;
  static const Uint8 DurationTag = 34;
  static const Uint8 OidIriTag = 35;
  static const Uint8 RelativeOidIriTag = 36;


  inline DerEncode( void )
    {
    }

  inline DerEncode( const DerEncode& in )
    {
    if( in.testForCopy )
      return;

    throw "DerEncode copy constructor.";
    }

  inline ~DerEncode( void )
    {
    }

  inline bool getIsContextSpec( void )
    {
    return isContextSpec;
    }

  Int32 readOneTag( const CharBuf& cBuf,
                    const Int32 where,
                    bool& constructed );

  void showTag( Uint32 fullTagByte,
                Uint32 tagByte,
                CharBuf& statusBuf );

  void getValue( CharBuf& val ) const;

  inline Uint32 getTag( void )
    {
    return tag;
    }

  inline Uint32 getLength( void )
    {
    return length;
    }


  };
