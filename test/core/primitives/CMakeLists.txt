#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(address)
add_subdirectory(block)
add_subdirectory(ticket)
add_subdirectory(tipset)

addtest(big_int_test
    big_int_test.cpp
    )
target_link_libraries(big_int_test
    Boost::boost
    )
