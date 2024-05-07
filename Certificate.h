// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "DerEncode.h"
// #include "DerEncodeLoop.h"
#include "../Network/Alerts.h"
#include "../Network/Results.h"
#include "../CppBase/FileIO.h"
#include "../Network/TlsMain.h"


// RFC 5280 is the main one.

// RFC 3279, RFC 4055, and
// RFC 4491.

// RFC 6818, 8398, 8399.



class Certificate
  {
  private:
  bool testForCopy = false;
  CharBuf statusBuf;
  // const char* statusFileName =
  //  "\\Eric\\main\\AIData\\CertStatus.txt";

  Integer serialNum;
  Integer pubKeyNum;

  public:
  Certificate( void )
    {
    }

  Certificate( const Certificate& in )
    {
    if( in.testForCopy )
      return;

    throw "Certificate copy constructor.";
    }

  ~Certificate( void )
    {
    }

  Uint32 parseOneCert( const CharBuf& certBuf,
                        TlsMain& tlsMain );

  Uint32 parseTbsCert( const CharBuf& certBuf,
                       TlsMain& tlsMain );

  Int32 parseVersion( const CharBuf& certBuf );

  Int32 parseSerialNum(
                    const CharBuf& certBuf,
                    const Int32 nextIn,
                    TlsMain& tlsMain );

  Int32 parseTbsSigAlgID(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    );

  Int32 parseIssuer( const CharBuf& certBuf,
                     const Int32 nextIn // ,
                     // TlsMain& tlsMain
                     );

  Int32 parseValidity( const CharBuf& certBuf,
                       const Int32 nextIn // ,
                       // TlsMain& tlsMain
                       );

  Int32 parseSubject( const CharBuf& certBuf,
                      const Int32 nextIn // ,
                      // TlsMain& tlsMain
                      );

  Int32 parseSubjectPubKey(
                    const CharBuf& certBuf,
                    const Int32 nextIn,
                    TlsMain& tlsMain );

  Int32 parseUniqueID( const CharBuf& certBuf,
                       const Int32 nextIn );

  void parseExtensions(
                    const CharBuf& certBuf,
                    const Int32 nextIn // ,
                    // TlsMain& tlsMain
                    );

  Uint32 parseAlgID( const CharBuf& certBuf // ,
                     // TlsMain& tlsMain
                     );


  };
