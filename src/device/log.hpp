
#include <cstddef>
#include <string>

#include "ringct/rctOps.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/account.h"
#pragma once


namespace hw {
    namespace ledger {

        void buffer_to_str(char *to,  const char *buff, int len) ;
        void bufferLE_to_str(char *to,  const char *buff, int len);

        void log_hexbuffer(std::string msg,  const char* buff, int len);
        void log_hexbufferLE(std::string msg,  const char* buff, int len);
        void log_message(std::string msg,  std::string info );
#ifdef DEBUGLEDGER
        #define TRACK printf("file %s:%d\n",__FILE__, __LINE__)
        //#define TRACK MCDEBUG("ledger"," At file " << __FILE__ << ":" << __LINE__)
        //#define TRACK while(0);

        void decrypt(char* buf, int len) ;
        crypto::key_derivation decrypt(const crypto::key_derivation &derivation) ;
        cryptonote::account_keys decrypt(const cryptonote::account_keys& keys) ;
        crypto::secret_key decrypt(const crypto::secret_key &sec) ;
        rct::key  decrypt(const rct::key &sec);
        crypto::ec_scalar decrypt(const crypto::ec_scalar &res);
        rct::keyV decrypt(const rct::keyV &keys);

        void check32(std::string msg, std::string info, const char *h, const char *d, bool crypted=false);
        void check8(std::string msg, std::string info, const char *h, const char *d,  bool crypted=false);

        void set_check_verbose(bool verbose);

    #endif
    }
}
