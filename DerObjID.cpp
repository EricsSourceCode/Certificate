// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#include "DerObjID.h"
#include "../CppBase/StIO.h"



// static
void DerObjID::makeFromCharBuf(
              const CharBuf& inBuf,
              CharBuf& outBuf )
{
outBuf.clear();

const Int32 last = inBuf.getLast();
if( last < 2 )
  throw "DerObjID Length too short.";

Int32 firstOIDByte = inBuf.getU8( 0 );
// 1.2.840.113549
// The first two numbers (like 1.2) are
// put in the first byte.
// Part1 can only be 1, 2 or 3.
Int32 part1 = firstOIDByte / 40;
Int32 part2 = firstOIDByte % 40;

CharBuf part1Buf( part1 );
CharBuf part2Buf( part2 );

outBuf.appendCharBuf( part1Buf );
outBuf.appendChar( '.' );
outBuf.appendCharBuf( part2Buf );
outBuf.appendChar( '.' );

Int32 where = 1;
CharBuf holdOneBuf;
CharBuf numberBuf;

// while( don't do this forever )
for( Int32 countW = 0; countW < 100; countW++ )
  {
  holdOneBuf.clear();
  if( where >= last )
    break;

  for( int count = 0; count < 8; count++ )
    {
    if( where >= last )
      break;

    Uint8 oneByte = inBuf.getU8( where );
    where++;

    holdOneBuf.appendU8( oneByte & 0x7F );

    // The high bit marks it for
    // continuing or not.
    if( (oneByte & 0x80) == 0 )
      break;

    }

  Uint64 oneNumber = getOneNumber(
                           holdOneBuf );

  numberBuf.setFromUint64( oneNumber );
  outBuf.appendCharBuf( numberBuf );
  outBuf.appendChar( '.' );
  }

// Get rid of that last period on
// the end.

Int32 truncTo = outBuf.getLast() - 1;
outBuf.truncateLast( truncTo );
}



// static
Uint64 DerObjID::getOneNumber(
                          CharBuf& codedBytes )
{
const Int32 last = codedBytes.getLast();
if( last < 1 )
  return 0;

if( last >= 8 )
  throw "DerObjID::getOneNumber last >= 8";

Uint64 nextValueParts = 0;
for( int count = 0; count < last; count++ )
  {
  nextValueParts <<= 8;
  // It starts out with a value of zero
  // so shifting zero left...
  nextValueParts |= codedBytes.getU8( count );
  }

// Now I have the parts of the number
// in base-128 form.
Uint64 base = 1;
Uint64 theNumber = 0;
for( Int32 count = 0; count < last; count++ )
  {
  theNumber += base * (nextValueParts & 0x7F);
  base = base * 128;
  nextValueParts >>= 8;
  }

return theNumber;
}
