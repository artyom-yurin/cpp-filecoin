/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto/blake2/blake2b160.hpp"

#include "crypto/blake2/blake2b.h"

namespace fc::crypto::blake2b {

  Blake2b160Hash blake2b_160(gsl::span<const uint8_t> to_hash) {
    Blake2b160Hash res{};
    ::blake2b(res.data(),
              BLAKE2B160_HASH_LENGTH,
              nullptr,
              0,
              to_hash.data(),
              to_hash.size());
    return res;
  }

  Blake2b256Hash blake2b_256(
      gsl::span<const uint8_t> to_hash) {
    Blake2b256Hash res{};
    ::blake2b(res.data(),
              BLAKE2B256_HASH_LENGTH,
              nullptr,
              0,
              to_hash.data(),
              to_hash.size());
    return res;
  }

    fc::outcome::result<Blake2b512Hash> blake2b_512(
            gsl::span<const uint8_t> to_hash) {
        Blake2b512Hash res{};
        if (::blake2b(res.data(),
                      BLAKE2B512_HASH_LENGTH,
                      nullptr,
                      0,
                      to_hash.data(),
                      to_hash.size())
            != 0)
            return Blake2bError::CANNOT_INIT;
        return res;
    }

}  // namespace fc::crypto::blake2b
