// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// See https://ericssourcecode.github.io/
// For guides and information.


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"


class DerBitStr
  {
  private:
  bool testForCopy = false;
  CharBuf cBuf;
  Uint64 allBits;

  public:
  DerBitStr( void )
    {
    }

  DerBitStr( const DerBitStr& in )
    {
    if( in.testForCopy )
      return;

    throw "DerBitStr copy constructor called.";
    }

  ~DerBitStr( void )
    {
    }

  void setCharBuf( const CharBuf& toSet )
    {
    cBuf.copy( toSet );

    const Int32 cBufLast = cBuf.getLast();
    if( cBufLast < 2 )
      throw "DerBitStr cBufLast < 2.";

    // The number of unused bits on the right
    // side of the bit string.
    Uint8 unusedBits = cBuf.getU8( 0 );

    StIO::printF( "unusedBits: " );
    StIO::printFUD( unusedBits );
    StIO::putLF();

    // 05 A0 means 5 unused bits on the right.
    // A is 10, which is 1010b.  Shifting right
    // 5 bits is: A0 >> 5 = 101b.
    // And it is Big Endian, so the bit on the
    // right side is bit zero.

    Uint64 moreBits = 0;
    allBits = cBuf.getU8( 1 );
    if( cBufLast > 2 )
      {
      moreBits = cBuf.getU8( 2 );
      moreBits <<= 8;
      allBits |= moreBits;
      }

    // if( cBufLast > 3 )

    allBits >>= unusedBits;
    }

  inline bool getBitAt( const Int32 where )
    {
    Uint64 checkBits = allBits >> where;
    if( (checkBits & 0x01) == 1 )
      return true;

    return false;
    }

  };
