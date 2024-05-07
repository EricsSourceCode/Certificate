// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#include "DerEncodeLoop.h"
#include "../CppBase/StIO.h"



Int32 DerEncodeLoop::readAllTags(
                   const CharBuf& cBuf,
                   const Int32 where,
                   CharBuf& statusBuf,
                   const Int32 level )
{
bool constructed = false;
DerEncode derEncode;

u16Buf.appendU16( DerEncode::LevelDelim );
u16Buf.appendU16( level & 0xFFFF );

Int32 next = where;
const Int32 reasonableCount = 100;
for( Int32 loops = 0; loops < reasonableCount;
                                   loops++ )
  {
  next = derEncode.readOneTag( cBuf, next,
                            constructed );
  if( next < 0 )
    return next;

  if( constructed )
    {
    CharBuf innerBuf;
    derEncode.getValue( innerBuf );

    // Recursive for all inner tags.
    // Int32 result =
    readAllTags( innerBuf, 0, statusBuf,
                               level + 1 );
    // if( result < 0 )

    // statusBuf.appendCharPt( "End of level.\n" );

    }
  }

return -1;
}
