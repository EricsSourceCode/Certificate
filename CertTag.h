// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once



#include "BasicTypes.h"
#include "CharBuf.h"


// One tag in a certificate.



class CertTag
  {
  private:
  bool testForCopy = false;

  // Data files have it in this order:
  Uint16 level = 0;
  Uint16 tag = 0;
  Uint32 length = 0;
  CharBuf value;

  public;
  CertTag( void )
    {
    }

  CertTag( const CertTag& in )
    {
    if( in.testForCopy )
      return;

    throw "CertTag copy constructor called.";
    }

  ~CertTag( void )
    {
    }


  };
