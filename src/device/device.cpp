#include "device_default.hpp"
#include "device_ledger.hpp"


#include "ringct/rctCryptoOps.h"
#include "ringct/rctOps.h"
#include "wallet/wallet2.h"

#include "common/scoped_message_writer.h"

namespace hw {


    /* ======================================================================= */
    /*  MAGIC LAMBDA SETUP                                                     */
    /* ======================================================================= */

    namespace {
        static std::map<std::string, Device&> registry;
        static int inited = []() -> int {
            //tools::scoped_message_writer w  = tools::msg_writer();
            //w << "Registering devices...";
            hw::core::register_all();
            hw::ledger::register_all();
            //w << "done.";

            return registry.size();
        }();
    }

    Device& register_device(std::string device_descriptor, Device& device) {
        //tools::scoped_message_writer w  = tools::success_msg_writer();
        registry.insert(std::make_pair(device_descriptor,std::ref(device)));
        return device;
    }


    Device& get_device(std::string device_descriptor) {
        auto device = registry.find(device_descriptor);
         if (device == registry.end()) {
            tools::fail_msg_writer()<< "Device not found "<<device_descriptor;
            throw std::runtime_error("device not found: "+ device_descriptor);
         }

         return device->second;
    }


    /* ======================================================================= */
    /*  DEVICE                                                                 */
    /* ======================================================================= */

    /* --- SETUP/TEARDOWN --- */
    bool Device::set_name(const std::string &name) {
        this->name = name;
        return true;
    }
    std::string Device::get_name() {
        return this->name;
    }
    bool Device::init(void) {
        dfns();
    }
    bool Device::release() {
        dfns();
    }

    bool Device::connect(void) {
        dfns();
    }
    bool Device::disconnect() {
        dfns();
    }

    /* --- WALLET & ADDRESS --- */
    bool  Device::get_public_address(cryptonote::account_public_address &pubkey) {
        dfns();
    }
    bool  Device::get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) {
        memset(viewkey.data, 0x00, 32);
        memset(spendkey.data, 0xFF, 32);
        return true;
    }
    bool  Device::generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key) {
        dfns();
    }

    /* --- SUB ADDRESS ---*/
    bool  Device::derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index,  crypto::public_key &derived_pub) {
        dfns();
    }
    bool  Device::get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index, crypto::public_key &D) {
        dfns();
    }
    
    bool  Device::get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end, std::vector<crypto::public_key> &pkeys) {
        dfns();
    }
    bool  Device::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index, cryptonote::account_public_address &address) {
        dfns();
    }
    bool  Device::get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index, crypto::secret_key &sub_sec) {
        dfns();
    }

    /* --- DERIVATION & KEY --- */
    bool  Device::verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
        dfns();
    }
    bool  Device::scalarmultKey(const rct::key &pub, const rct::key &sec, rct::key &mulkey) {
        dfns();
    }
    bool  Device::scalarmultBase(const rct::key &sec, rct::key &mulkey) {
        dfns();
    }
    bool  Device::sc_secret_add(const crypto::secret_key &a, const crypto::secret_key &b, crypto::secret_key &r) {
        dfns();
    }
    bool  Device::generate_keys(bool recover, const crypto::secret_key& recovery_key, crypto::public_key &pub, crypto::secret_key &sec, crypto::secret_key &rng) {
        dfns();
    }
    bool  Device::generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) {
        dfns();
    }
    bool  Device::derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) {
        dfns();
    }
    bool  Device::derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec,  crypto::secret_key &derived_sec) {
        dfns();
    }
    bool  Device::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub,  crypto::public_key &derived_pub) {
        dfns();
    }
    bool  Device::secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) {
        dfns();
    }
    bool  Device::generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) {
        dfns();
    }

    /* --- TRANSACTION --- */
    bool  Device::open_tx(crypto::secret_key &tx_key) {
        dfns();
    }
    bool  Device::get_additional_key(const bool subaddr, cryptonote::keypair &additional_txkey) {
        dfns();
    }
    bool  Device::set_signature_mode(unsigned int sig_mode) {
        dfns();
    }
    bool  Device::encrypt_payment_id(const crypto::public_key &public_key, const crypto::secret_key &secret_key, crypto::hash8 &payment_id ) {
        dfns();
    }
    bool  Device::ecdhEncode(const rct::key &AKout, rct::ecdhTuple &unmasked) {
        dfns();
    }
    bool  Device::ecdhDecode(const rct::key &AKout, rct::ecdhTuple &masked) {
        dfns();
    }
    bool  Device::add_output_key_mapping(const crypto::public_key &Aout, const crypto::public_key &Bout, size_t real_output_index,
                                                 const rct::key &amount_key,  const crypto::public_key &out_eph_public_key) {
        dfns();
    }
    bool  Device::mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) {
        dfns();
    }
    bool  Device::mlsag_prepare(const rct::key &H, const rct::key &xx, rct::key &a, rct::key &aG, rct::key &aHP, rct::key &rvII) {
        dfns();
    }
    bool  Device::mlsag_prepare(rct::key &a, rct::key &aG) {
        dfns();
    }
    bool  Device::mlsag_hash(const rct::keyV &long_message, rct::key &c) {
        dfns();
    }
    bool  Device::mlsag_sign(const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const int rows, const int dsRows, rct::keyV &ss) {
        dfns();
    }
    bool  Device::close_tx(void) {
        dfns();
    }


}