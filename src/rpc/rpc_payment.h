// Copyright (c) 2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma  once 

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <boost/serialization/version.hpp>
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{
  class rpc_payment
  {
  public:
    rpc_payment(const cryptonote::account_public_address &address, uint64_t diff, uint64_t credits_per_hash_found);
    bool pay(const crypto::public_key &client, uint64_t ts, uint64_t payment, const std::string &rpc, bool same_ts, uint64_t &credits);
    bool get_info(const crypto::public_key &client, const std::function<bool(const crypto::public_key&, cryptonote::block&)> &get_block_template, cryptonote::blobdata &hashing_blob, const crypto::hash &top, uint64_t &diff, uint64_t &credits_per_hash_found, uint64_t &credits);
    bool submit_nonce(const crypto::public_key &client, uint32_t nonce, const crypto::hash &top, std::string &error, uint64_t &credits, crypto::hash &hash, cryptonote::block &block);
    const cryptonote::account_public_address &get_payment_address() const { return m_address; }
    bool foreach(const std::function<bool(const crypto::public_key &client, uint64_t credits, uint64_t last_request_timestamp)> &f);

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
      a & m_client_info;
    }

    bool load(const std::string &directory);
    bool store(const std::string &directory = std::string());

  private:
    struct client_info
    {
      cryptonote::block block;
      cryptonote::blobdata hashing_blob;
      crypto::hash top;
      crypto::hash previous_top;
      uint64_t credits;
      std::unordered_set<uint64_t> payments;
      std::unordered_set<uint64_t> previous_payments;
      time_t update_time;
      uint64_t last_request_timestamp;

      client_info();

      template <class t_archive>
      inline void serialize(t_archive &a, const unsigned int ver)
      {
        a & block;
        a & hashing_blob;
        a & top;
        a & previous_top;
        a & credits;
        a & payments;
        a & previous_payments;
        a & update_time;
        a & last_request_timestamp;
      }
    };
    cryptonote::account_public_address m_address;
    uint64_t m_diff;
    uint64_t m_credits_per_hash_found;
    std::unordered_map<crypto::public_key, client_info> m_client_info;
    std::string m_directory;
  };
}

BOOST_CLASS_VERSION(cryptonote::rpc_payment, 0);
BOOST_CLASS_VERSION(cryptonote::rpc_payment::client_info, 0);
