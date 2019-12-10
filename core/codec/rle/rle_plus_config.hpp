/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CODEC_RLE_PLUS_CONFIG_HPP
#define CODEC_RLE_PLUS_CONFIG_HPP

#include <exception>

namespace fc::codec::rle {
  /**
   * @enum RLE+ constants
   * @details Object max size
   * https://filecoin-project.github.io/specs/#other-considerations
   */
  enum Config {
    SMALL_BLOCK_LENGTH = 0x04, /**< Num of bits to store small block value */
    PACK_BYTE_SHIFT = 0x07,    /**< Bitwise shift size for pack block value */
    BYTE_BITS_COUNT = 0x08,    /**< Num of bits in the byte */
    LONG_BLOCK_VALUE = 0x10,   /**< Value of the long block */
    UNPACK_BYTE_MASK = 0x7F,   /**< Bitwise mask for unpack long block value */
    BYTE_SLICE_VALUE = 0x80,   /**< MSB value */
    OBJECT_MAX_SIZE = 0x100000 /**< Maximum object size to encode or decode */
  };

};  // namespace fc::codec::rle

#endif
