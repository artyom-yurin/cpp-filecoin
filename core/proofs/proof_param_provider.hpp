/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CPP_FILECOIN_PROOF_PARAM_PROVIDER_HPP
#define CPP_FILECOIN_PROOF_PARAM_PROVIDER_HPP

#include "boost/thread/mutex.hpp"
#include "common/outcome.hpp"
#include "gsl/span"

namespace fc::proofs {

  struct paramFile {
    std::string name;
    std::string cid;
    std::string digest;
    uint64_t sector_size;
  };

  class ProofParamProvider {
   public:
    static outcome::result<void> getParams(
        const std::vector<paramFile> &param_files, uint64_t storage_size);

    static outcome::result<void> checkFile(const std::string &path,
                                           const paramFile &info);

    static outcome::result<std::vector<paramFile>> readJson(
        const std::string &path);

   private:
    static void fetch(const paramFile &info);

    static boost::mutex fetch_mutex_;
  };

}  // namespace fc::proofs

#endif  // CPP_FILECOIN_PROOF_PARAM_PROVIDER_HPP
