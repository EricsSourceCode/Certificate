// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// See https://ericssourcecode.github.io/
// For guides and information.


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "../Network/Alerts.h"
#include "../Network/Results.h"
#include "../Network/TlsMain.h"


// This is for the whole Certificate Message
// in RFC 8446 section-4.4.2: Certificate



class CertMesg
  {
  private:
  bool testForCopy = false;

  public:
  CertMesg( void )
    {
    }

  CertMesg( const CertMesg& in )
    {
    if( in.testForCopy )
      return;

    throw "CertMesg copy constructor.";
    }

  ~CertMesg( void )
    {
    }

  Uint32 parseCertMsg( const CharBuf& certBuf,
                       TlsMain& tlsMain );

  };
