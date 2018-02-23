// Copyright (c) 2017-2018, The Monero Project
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
//

#pragma once

#include "device.hpp"

namespace hw {

    namespace core {

        void register_all();

        class DeviceDefault : public hw::Device {
        public:
            DeviceDefault();
            DeviceDefault(const DeviceDefault &device);
            ~DeviceDefault();

            DeviceDefault& operator=(const DeviceDefault &device);
            explicit operator bool() const { return false; };

             /* ======================================================================= */
            /*                              SETUP/TEARDOWN                             */
            /* ======================================================================= */


            /* ======================================================================= */
            /*                             WALLET & ADDRESS                            */
            /* ======================================================================= */
            //bool  get_public_address(cryptonote::account_public_address &pubkey);
            #ifdef DEBUGLEDGER
            //bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey);
            #endif
            bool  generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key);


            /* ======================================================================= */
            /*                               SUB ADDRESS                               */
            /* ======================================================================= */
            bool  derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index,  crypto::public_key &derived_pub);
            bool  get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index, crypto::public_key &D);
            bool  get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end, std::vector<crypto::public_key> &pkeys);
            bool  get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index, cryptonote::account_public_address &address);
            bool  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index, crypto::secret_key &sub_sec);

            /* ======================================================================= */
            /*                            DERIVATION & KEY                             */
            /* ======================================================================= */
            bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) ;
            bool  scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a);
            bool  scalarmultBase(rct::key &aG, const rct::key &a);
            bool  sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b);
            bool  generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key, bool recover, crypto::secret_key &rng);
            bool  generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation);
            bool  derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res);
            bool  derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec,  crypto::secret_key &derived_sec);
            bool  derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub,  crypto::public_key &derived_pub);
            bool  secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub);
            bool  generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image);


            /* ======================================================================= */
            /*                               TRANSACTION                               */
            /* ======================================================================= */

            bool  open_tx(crypto::secret_key &tx_key);

            //bool  get_additional_key(const bool subaddr, cryptonote::keypair &additional_txkey);
            bool  set_signature_mode(unsigned int sig_mode);

            bool  encrypt_payment_id(const crypto::public_key &public_key, const crypto::secret_key &secret_key, crypto::hash8 &payment_id );

            bool  ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec);
            bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec);

            bool  add_output_key_mapping(const crypto::public_key &Aout, const crypto::public_key &Bout, size_t real_output_index,
                                                const rct::key &amount_key,  const crypto::public_key &out_eph_public_key);


            bool  mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash);
            bool  mlsag_prepare(const rct::key &H, const rct::key &xx, rct::key &a, rct::key &aG, rct::key &aHP, rct::key &rvII);
            bool  mlsag_prepare(rct::key &a, rct::key &aG);
            bool  mlsag_hash(const rct::keyV &long_message, rct::key &c);
            bool  mlsag_sign(const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss);

            bool  close_tx(void);
        };

    }



}

