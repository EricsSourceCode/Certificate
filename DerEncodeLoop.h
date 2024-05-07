// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "../CppBase/Uint16Buf.h"
#include "DerEncode.h"



// DER: Distinguished Encoding Rules.
// See DerEncode.cpp for notes.



class DerEncodeLoop
  {
  private:
  bool testForCopy = false;
  Uint16Buf u16Buf;

  public:
  DerEncodeLoop( void )
    {
    }

  DerEncodeLoop( const DerEncodeLoop& in )
    {
    if( in.testForCopy )
      return;

    throw "DerEncodeLoop copy constructor.";
    }

  ~DerEncodeLoop( void )
    {
    }

  Int32 readAllTags( const CharBuf& cBuf,
                     const Int32 where,
                     CharBuf& statusBuf,
                     const Int32 level );

  };
