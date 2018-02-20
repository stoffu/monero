#include "misc_log_ex.h"
#include "log.hpp"

namespace hw {
    namespace ledger {

    void buffer_to_str(char *to,  const char *buff, int len) {
      for (int i=0; i<len; i++) {
        sprintf(to+2*i, "%.02x", (unsigned char)buff[i]);
      }
    }
    void bufferLE_to_str(char *to,  const char *buff, int len) {
      for (int i=0; i<len; i++) {
        sprintf(to+2*i, "%.02x", (unsigned char)buff[31-i]);
      }
    }

    void log_hexbuffer(std::string msg,  const char* buff, int len) {
      char logstr[1024];
      buffer_to_str(logstr,  buff, len);
      MCDEBUG("ledger", msg<< ": " << logstr);
    }

    void log_hexbufferLE(std::string msg,  const char* buff, int len) {
      char logstr[1024];
      bufferLE_to_str(logstr,  buff, len);
      MCDEBUG("ledger", msg<< ": " << logstr);
    }

    void log_message(std::string msg,  std::string info ) {
      MCDEBUG("ledger", msg << ": " << info);
    }

    #ifdef DEBUGLEDGER
    extern crypto::secret_key viewkey;
    extern crypto::secret_key spendkey;


    void decrypt(char* buf, int len) {
      #ifdef IODUMMYCRYPT
      int i;
      if (len == 32) {
        //view key?
        for (i = 0; i<32; i++) {
          if (buf[i] != 0) break;
        }
        if (i == 32) {
          memmove(buf, hw::ledger::viewkey.data, 32);
          return;
        }
        //spend key?
        for (i = 0; i<32; i++) {
          if (buf[i] != (char)0xff) break;
        }
        if (i == 32) {
          memmove(buf, hw::ledger::spendkey.data, 32);
          return;
        }
      }
      //std decrypt: XOR.55h
      for (i = 0; i<len;i++) {
          buf[i] ^= 0x55;
        }
      #endif
    }

    crypto::key_derivation decrypt(const crypto::key_derivation &derivation) {
       crypto::key_derivation x = derivation;
       decrypt(x.data, 32);
       return x;
    }

    cryptonote::account_keys decrypt(const cryptonote::account_keys& keys) {
       cryptonote::account_keys x = keys;
       decrypt(x.m_view_secret_key.data, 32);
       decrypt(x.m_spend_secret_key.data, 32);
       return x;
    }


    crypto::secret_key decrypt(const crypto::secret_key &sec) {
       crypto::secret_key  x = sec;
       decrypt(x.data, 32);
       return x;
    }

    rct::key  decrypt(const rct::key &sec)  {
         rct::key  x = sec;
       decrypt((char*)x.bytes, 32);
       return x;
    }

    crypto::ec_scalar decrypt(const crypto::ec_scalar &res)  {
       crypto::ec_scalar  x = res;
       decrypt((char*)x.data, 32);
       return x;
    }

    rct::keyV decrypt(const rct::keyV &keys) {
        rct::keyV x ;
        for (unsigned int j = 0; j<keys.size(); j++) {
            x.push_back(decrypt(keys[j]));
        }
        return x;
    }

    static void check(std::string msg, std::string info, const char *h, const char *d, int len, bool crypted) {
      char dd[32];
      char logstr[128];

      memmove(dd,d,len);
      if (crypted) {
        decrypt(dd,len);
      }

      if (memcmp(h,dd,len)) {
          log_message("ASSERT EQ FAIL",  msg + ": "+ info );
          log_hexbuffer("    host  ", h, len);
          log_hexbuffer("    device", dd, len);

      } else {
        buffer_to_str(logstr,  dd, len);
        log_message("ASSERT EQ OK",  msg + ": "+ info + ": "+ std::string(logstr) );
      }
    }

    void check32(std::string msg, std::string info, const char *h, const char *d, bool crypted) {
      check(msg, info, h, d, 32, crypted);
    }

    void check8(std::string msg, std::string info, const char *h, const char *d, bool crypted) {
      check(msg, info, h, d, 8, crypted);
    }
  #endif
  }
}