/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CPP_FILECOIN_CORE_PROOFS_HPP
#define CPP_FILECOIN_CORE_PROOFS_HPP

#include <vector>
#include "common/blob.hpp"
#include "common/outcome.hpp"

using fc::common::Blob;

namespace fc::proofs {

  const int CommitmentBytesLen = 32;

  class RawSealPreCommitOutput {
   public:
    fc::common::Blob<CommitmentBytesLen> comm_d;
    fc::common::Blob<CommitmentBytesLen> comm_r;
  };

  // PieceMetadata represents a piece stored by the sector builder.
  class PieceMetadata {
   public:
    std::string key;
    uint64_t size;
    fc::common::Blob<CommitmentBytesLen> comm_p;
  };

  // SealTicket is required for the first step of Interactive PoRep.
  class SealTicket {
   public:
    uint64_t block_height;
    fc::common::Blob<CommitmentBytesLen> ticket_bytes;
  };

  // SealSeed is required for the second step of Interactive PoRep.
  class SealSeed {
   public:
    uint64_t block_height;
    fc::common::Blob<CommitmentBytesLen> ticket_bytes;
  };

  class SealCommitOutput {
   public:
    uint64_t sector_id;
    fc::common::Blob<CommitmentBytesLen> comm_d;
    fc::common::Blob<CommitmentBytesLen> comm_r;
    std::vector<uint8_t> proof;
    std::vector<PieceMetadata> pieces;
    SealTicket ticket;
    SealSeed seed;
  };

  class PublicPieceInfo {
   public:
    uint64_t size;
    fc::common::Blob<CommitmentBytesLen> comm_p;
  };

  class PublicSectorInfo {
   public:
    uint64_t sector_id;
    fc::common::Blob<CommitmentBytesLen> comm_r;
  };

  class SortedPublicSectorInfo {
   public:
    std::vector<PublicSectorInfo> f;
  };

  class PrivateSectorInfo {
   public:
    uint64_t sector_id;
    fc::common::Blob<CommitmentBytesLen> comm_r;
    std::string cache_dir_path;
    std::string sealed_sector_path;
  };

  class SortedPrivateSectorInfo {
   public:
    std::vector<PrivateSectorInfo> f;
  };

  class Candidate {
   public:
    uint64_t sector_id;
    fc::common::Blob<32> partial_ticket;
    fc::common::Blob<32> ticket;
    uint64_t sector_challenge_index;
  };

  class WriteWithoutAlignmentResult {
   public:
    uint64_t total_write_unpadded;
    fc::common::Blob<CommitmentBytesLen> comm_p;
  };

  class WriteWithAlignmentResult {
   public:
    uint64_t left_alignment_unpadded;
    uint64_t total_write_unpadded;
    fc::common::Blob<CommitmentBytesLen> comm_p;
  };

  outcome::result<fc::proofs::WriteWithoutAlignmentResult>
  writeWithoutAlignment(const std::string &piece_file_path,
                        const uint64_t piece_bytes,
                        const std::string &staged_sector_file_path);

  outcome::result<fc::proofs::WriteWithAlignmentResult> writeWithAlignment(
      const std::string &piece_file_path,
      const uint64_t piece_bytes,
      const std::string &staged_sector_file_path,
      const std::vector<uint64_t> &existing_piece_sizes);

  outcome::result<RawSealPreCommitOutput> sealPreCommit(
      const uint64_t sector_size,
      const uint8_t porep_proof_partitions,
      const std::string &cache_dir_path,
      const std::string &staged_sector_path,
      const std::string &sealed_sector_path,
      const uint64_t sector_id,
      const fc::common::Blob<32> &prover_id,
      const fc::common::Blob<32> &ticket,
      const std::vector<PublicPieceInfo> &pieces);

  outcome::result<std::vector<uint8_t>> sealCommit(
      const uint64_t sector_size,
      const uint8_t porep_proof_partitions,
      const std::string &cache_dir_path,
      const uint64_t sector_id,
      const fc::common::Blob<32> &prover_id,
      const fc::common::Blob<32> &ticket,
      const fc::common::Blob<32> &seed,
      const std::vector<PublicPieceInfo> &pieces,
      const RawSealPreCommitOutput &rspco);

  outcome::result<fc::common::Blob<32>> generatePieceCommitmentFromFile(
      const std::string &piece_file, const uint64_t piece_size);

  outcome::result<std::vector<Candidate>> generateCandidates(
      const uint64_t sector_size,
      const fc::common::Blob<32> &prover_id,
      const fc::common::Blob<32> &randomness,
      const uint64_t challenge_count,
      const SortedPrivateSectorInfo &sorted_private_sector_info);

  outcome::result<std::vector<uint8_t>> generatePoSt(
      const uint64_t sectorSize,
      const fc::common::Blob<32> &prover_id,
      const SortedPrivateSectorInfo &private_sector_info,
      const fc::common::Blob<32> &randomness,
      const std::vector<Candidate> &winners);

  outcome::result<bool> verifySeal(const uint64_t sector_size,
                                   const fc::common::Blob<CommitmentBytesLen> &comm_r,
                                   const fc::common::Blob<CommitmentBytesLen> &comm_d,
                                   const fc::common::Blob<32> &prover_id,
                                   const fc::common::Blob<32> &ticket,
                                   const fc::common::Blob<32> &seed,
                                   const uint64_t sector_id,
                                   const std::vector<uint8_t> proof);

  outcome::result<bool> verifyPoSt(const uint64_t sector_size,
                                   const SortedPublicSectorInfo &sector_info,
                                   const fc::common::Blob<32> &randomness,
                                   const uint64_t challenge_count,
                                   const std::vector<uint8_t> &proof,
                                   const std::vector<Candidate> &winners,
                                   const fc::common::Blob<32> &prover_id);

}  // namespace fc::proofs

#endif  // CPP_FILECOIN_CORE_PROOFS_HPP
