/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "proofs/proof_param_provider_error.hpp"

OUTCOME_CPP_DEFINE_CATEGORY(fc::proofs, ProofParamProviderError, e) {
  using fc::proofs::ProofParamProviderError;

  switch (e) {
    case (ProofParamProviderError::CHECKSUM_MISMATCH):
      return "ParamProvider: checksum mismatch";
    case (ProofParamProviderError::FILE_DOES_NOT_OPEN):
      return "ParamProvider: file does not open";
  }

  return "unknown error";
}
