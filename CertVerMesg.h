// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// See https://ericinarizona.github.io/
// For guides and information.


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
// #include "DerEncode.h"
#include "../Network/Alerts.h"
#include "../Network/Results.h"
#include "../Network/TlsMain.h"


// RFC 8446 section-4.4.3
// Certificate Verify


class CertVerMesg
  {
  private:
  bool testForCopy = false;

  public:
  CertVerMesg( void )
    {
    }

  CertVerMesg( const CertVerMesg& in )
    {
    if( in.testForCopy )
      return;

    throw "CertVerMesg copy constructor.";
    }

  ~CertVerMesg( void )
    {
    }

  Uint32 parseCertVerMsg(
                  const CharBuf& certVerBuf,
                  TlsMain& tlsMain );

  };
