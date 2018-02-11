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

#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include "cryptonote_config.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "common/int-util.h"
#include "serialization/crypto.h"
#include "common/unordered_containers_boost_serialization.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/difficulty.h"
#include "rpc_payment.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc.payment"

#define STALE_THRESHOLD 15 /* seconds */

#define PENALTY_FOR_STALE 2
#define PENALTY_FOR_BAD_HASH 20
#define PENALTY_FOR_DUPLICATE 20

namespace cryptonote
{
  rpc_payment::client_info::client_info():
    top(crypto::null_hash),
    credits(0),
    update_time(time(NULL)),
    last_request_timestamp(0)
  {
  }

  rpc_payment::rpc_payment(const cryptonote::account_public_address &address, uint64_t diff, uint64_t credits_per_hash_found):
    m_address(address),
    m_diff(diff),
    m_credits_per_hash_found(credits_per_hash_found)
  {
  }

  bool rpc_payment::pay(const crypto::public_key &client, uint64_t ts, uint64_t payment, const std::string &rpc, bool same_ts, uint64_t &credits)
  {
    client_info &info = m_client_info[client]; // creates if not found
    if (ts < info.last_request_timestamp || (ts == info.last_request_timestamp && !same_ts))
    {
      MDEBUG("Invalid ts: " << ts << " <= " << info.last_request_timestamp);
      return false;
    }
    info.last_request_timestamp = ts;
    if (info.credits < payment)
    {
      MDEBUG("Not enough credits: " << info.credits << " < " << payment);
      return false;
    }
    info.credits -= payment;
    MDEBUG("client " << client << " paying " << payment << " for " << rpc << ", " << info.credits << " left");
    credits = info.credits;
    return true;
  }

  bool rpc_payment::get_info(const crypto::public_key &client, const std::function<bool(const crypto::public_key&, cryptonote::block&)> &get_block_template, cryptonote::blobdata &hashing_blob, const crypto::hash &top, uint64_t &diff, uint64_t &credits_per_hash_found, uint64_t &credits)
  {
    client_info &info = m_client_info[client]; // creates if not found
    const time_t now = time(NULL);
    bool need_template = top != info.top;
    if (need_template)
    {
      if (!get_block_template(client, info.block))
        return false;
      hashing_blob = get_block_hashing_blob(info.block);
      info.previous_top = info.top;
      info.previous_payments = info.payments;
      if (info.hashing_blob != hashing_blob)
        info.payments.clear();
else MGINFO("WEIRD");
      info.hashing_blob = hashing_blob;
    }
    info.top = top;
    info.update_time = now;
    hashing_blob = info.hashing_blob;
    diff = m_diff;
    credits_per_hash_found = m_credits_per_hash_found;
    credits = info.credits;
    return true;
  }

  bool rpc_payment::submit_nonce(const crypto::public_key &client, uint32_t nonce, const crypto::hash &top, std::string &error, uint64_t &credits, crypto::hash &hash, cryptonote::block &block)
  {
    client_info &info = m_client_info[client]; // creates if not found
    MINFO("client " << client << " sends nonce: " << nonce);
    const bool is_current = top == info.top;
    std::unordered_set<uint64_t> &payments = is_current ? info.payments : info.previous_payments;
    if (payments.find(nonce) != payments.end())
    {
      MWARNING("Duplicate nonce " << nonce << " from " << (is_current ? "current" : "previous"));
      error = "Duplicate payment";
      info.credits = std::max(info.credits, PENALTY_FOR_DUPLICATE * m_credits_per_hash_found) - PENALTY_FOR_DUPLICATE * m_credits_per_hash_found;
      return false;
    }
    payments.insert(nonce);

    if (info.hashing_blob.size() < 43)
    {
      // not initialized ?
      error = "not initialized";
      return false;
    }

    if (!is_current)
    {
      const time_t now = time(NULL);
      if (now > info.update_time + STALE_THRESHOLD)
      {
        MWARNING("Nonce is stale (top " << top << ", should be " << info.top << " or within " << STALE_THRESHOLD << " seconds");
        error = "stale";
        info.credits = std::max(info.credits, PENALTY_FOR_STALE * m_credits_per_hash_found) - PENALTY_FOR_STALE * m_credits_per_hash_found;
        return false;
      }
    }

    cryptonote::blobdata hashing_blob = info.hashing_blob;
    *(uint32_t*)(hashing_blob.data() + 39) = SWAP32LE(nonce);
    const int cn_variant = hashing_blob[0] >= 7 ? hashing_blob[0] - 6 : 0;
    crypto::cn_slow_hash(hashing_blob.data(), hashing_blob.size(), hash, cn_variant);
    if (!check_hash(hash, m_diff))
    {
      MWARNING("Payment too low");
      error = "Payment too low";
      info.credits = std::max(info.credits, PENALTY_FOR_BAD_HASH * m_credits_per_hash_found) - PENALTY_FOR_BAD_HASH * m_credits_per_hash_found;
      return false;
    }

    if (info.credits > std::numeric_limits<uint64_t>::max() - m_credits_per_hash_found)
      info.credits = std::numeric_limits<uint64_t>::max();
    else
      info.credits += m_credits_per_hash_found;
    MINFO("client " << client << " credited for " << m_credits_per_hash_found << ", now " << info.credits << (is_current ? "" : " (close)"));

    credits = info.credits;
    info.block.nonce = nonce;
    block = info.block;
    return true;
  }

  bool rpc_payment::foreach(const std::function<bool(const crypto::public_key &client, uint64_t credits, uint64_t last_request_timestamp)> &f)
  {
    for (std::unordered_map<crypto::public_key, client_info>::const_iterator i = m_client_info.begin(); i != m_client_info.end(); ++i)
    {
      if (!f(i->first, i->second.credits, i->second.last_request_timestamp))
        return false;
    }
    return true;
  }

  bool rpc_payment::load(const std::string &directory)
  {
    TRY_ENTRY();
    m_directory = directory;
    MINFO("loading rpc payments data from " << directory);
    std::string state_file_path = directory + "/" + RPC_PAYMENTS_DATA_FILENAME;
    std::ifstream data;
    data.open(state_file_path, std::ios_base::binary | std::ios_base::in);
    if (!data.fail())
    {
      try
      {
        // first try reading in portable mode
        boost::archive::portable_binary_iarchive a(data);
        a >> *this;
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to load RPC payments file");
        m_client_info.clear();
      }
    }
    else
    {
      m_client_info.clear();
    }

    CATCH_ENTRY_L0("rpc_payment::load", false);
    return true;
  }

  bool rpc_payment::store(const std::string &directory_)
  {
    TRY_ENTRY();
    const std::string &directory = directory_.empty() ? m_directory : directory_;
    MINFO("storing rpc payments data to " << directory);
    if (!tools::create_directories_if_necessary(directory))
    {
      MWARNING("Failed to create data directory: " << directory);
      return false;
    }
    std::string state_file_path = directory + "/" + RPC_PAYMENTS_DATA_FILENAME;
    std::ofstream data;
    data.open(state_file_path, std::ios_base::binary | std::ios_base::out | std::ios::trunc);
    if (data.fail())
    {
      MWARNING("Failed to save RPC payments to file " << state_file_path);
      return false;
    };
    boost::archive::portable_binary_oarchive a(data);
    a << *this;
    return true;
    CATCH_ENTRY_L0("rpc_payment::store", false);
    return true;
  }
}
