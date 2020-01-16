#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(proof_param_provider
        proof_param_provider.cpp
        )

target_link_libraries(proof_param_provider
        Boost::system
        outcome
        )

add_library(proofs
        proofs.cpp
        proofs_error.cpp
        )

target_link_libraries(proofs
        filecoin_ffi
        outcome
        blob
        proof_param_provider
        )
