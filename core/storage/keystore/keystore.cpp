/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keystore.hpp"

#include "common/visitor.hpp"

using fc::storage::keystore::KeyStore;
using fc::storage::keystore::KeyStoreError;

KeyStore::KeyStore(std::shared_ptr<BlsProvider> blsProvider,
                   std::shared_ptr<Secp256k1Provider> secp256K1Provider)
    : bls_provider_(std::move(blsProvider)),
      secp256k1_provider_(std::move(secp256K1Provider)) {}

fc::outcome::result<bool> KeyStore::CheckAddress(
    const Address &address, const TPrivateKey &key) noexcept {
  // TODO(a.chernyshov)wait for address implementation
  // https://github.com/filecoin-project/cpp-filecoin/pull/16
  return (address == 1 || address == 2);
}

fc::outcome::result<KeyStore::TSignature> KeyStore::Sign(
    const Address &address, gsl::span<uint8_t> data) noexcept {
  OUTCOME_TRY(private_key, Get(address));
  OUTCOME_TRY(valid, CheckAddress(address, private_key));
  if (!valid) return KeyStoreError::WRONG_ADDRESS;

  // TODO(a.chernyshov)wait for address implementation
  // https://github.com/filecoin-project/cpp-filecoin/pull/16
  if (address == 1) {
    OUTCOME_TRY(
        signature,
        bls_provider_->sign(data, boost::get<BlsPrivateKey>(private_key)));
    return signature;
  }
  if (address == 2) {
    OUTCOME_TRY(signature,
                secp256k1_provider_->sign(
                    data, boost::get<Secp256k1PrivateKey>(private_key)));
    return std::move(signature);
  }

  return KeyStoreError::WRONG_ADDRESS;
}

fc::outcome::result<bool> KeyStore::Verify(
    const Address &address,
    const gsl::span<uint8_t> &data,
    const TSignature &signature) noexcept {
  OUTCOME_TRY(private_key, Get(address));
  OUTCOME_TRY(valid, CheckAddress(address, private_key));
  if (!valid) return KeyStoreError::WRONG_ADDRESS;

  try {
    // TODO(a.chernyshov)wait for address implementation
    // https://github.com/filecoin-project/cpp-filecoin/pull/16
    if (address == 1) {
      OUTCOME_TRY(public_key,
                  bls_provider_->derivePublicKey(
                      boost::get<BlsPrivateKey>(private_key)));
      auto bls_signature = boost::get<BlsSignature>(signature);
      OUTCOME_TRY(
          res, bls_provider_->verifySignature(data, bls_signature, public_key));
      return res;
    }
    if (address == 2) {
      OUTCOME_TRY(public_key,
                  secp256k1_provider_->derivePublicKey(
                      boost::get<Secp256k1PrivateKey>(private_key)));
      auto secp256k1_signature = boost::get<Secp256k1Signature>(signature);
      OUTCOME_TRY(
          res,
          secp256k1_provider_->verify(data, secp256k1_signature, public_key));
      return res;
    }
  } catch (std::exception &) {
    return KeyStoreError::WRONG_SIGNATURE;
  }

  return KeyStoreError::UNKNOWN;
}
