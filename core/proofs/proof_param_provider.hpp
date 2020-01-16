/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CPP_FILECOIN_PROOF_PARAM_PROVIDER_HPP
#define CPP_FILECOIN_PROOF_PARAM_PROVIDER_HPP

#include "common/outcome.hpp"
#include "boost/thread/mutex.hpp"

namespace fc::proofs {

  struct paramFile {
    std::string cid;
    std::string digest;
    uint64_t sector_size;
  };

  class ProofParamProvider {
   public:
    static outcome::result<void> getParams(
        const std::vector<uint8_t> &param_bytes, uint64_t storage_size);

   private:
    static outcome::result<void> fetch(const std::string &name,
                                       const paramFile &info);

    static boost::mutex fetch_mutex_;
  };

}  // namespace fc::proofs

#endif  // CPP_FILECOIN_PROOF_PARAM_PROVIDER_HPP
