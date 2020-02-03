/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "proofs/proofs.hpp"

#include <fcntl.h>
#include <filecoin-ffi/filecoin.h>
#include <boost/filesystem/fstream.hpp>
#include <iostream>
#include "proofs/proofs_error.hpp"

namespace fc::proofs {

  // ******************
  // TO CPP CASTED FUNCTIONS
  // ******************

  Candidate cppCandidate(const FFICandidate *c_candidate) {
    Candidate candidate;
    candidate.sector_id = c_candidate->sector_id;
    candidate.sector_challenge_index = c_candidate->sector_challenge_index;
    for (size_t i = 0; i < candidate.ticket.size(); i++) {
      candidate.ticket[i] = c_candidate->ticket[i];
    }
    for (size_t i = 0; i < candidate.partial_ticket.size(); i++) {
      candidate.partial_ticket[i] = c_candidate->partial_ticket[i];
    }
    return candidate;
  }

  std::vector<Candidate> cppCandidates(const FFICandidate *candidates_ptr,
                                       size_t size) {
    std::vector<Candidate> cpp_candidates;
    if (candidates_ptr == nullptr || size == 0) {
      return cpp_candidates;
    }

    for (size_t i = 0; i < size; i++) {
      auto current_candidate = candidates_ptr + i;
      cpp_candidates.push_back(cppCandidate(current_candidate));
    }

    return cpp_candidates;
  }

  RawSealPreCommitOutput cppRawSealPreCommitOutput(
      const FFISealPreCommitOutput &c_seal_pre_commit_output) {
    RawSealPreCommitOutput cpp_seal_pre_commit_output;

    for (size_t i = 0; i < CommitmentBytesLen; i++) {
      cpp_seal_pre_commit_output.comm_d[i] = c_seal_pre_commit_output.comm_d[i];
      cpp_seal_pre_commit_output.comm_r[i] = c_seal_pre_commit_output.comm_r[i];
    }

    return cpp_seal_pre_commit_output;
  }

  WriteWithoutAlignmentResult cppWriteWithoutAlignmentResult(
      const uint64_t total_write_unpadded, const uint8_t *comm_p) {
    WriteWithoutAlignmentResult result;

    result.total_write_unpadded = total_write_unpadded;
    for (size_t i = 0; i < CommitmentBytesLen; i++) {
      result.comm_p[i] = comm_p[i];
    }

    return result;
  }

  WriteWithAlignmentResult cppWriteWithAlignmentResult(
      const uint64_t left_alignment_unpadded,
      const uint64_t total_write_unpadded,
      const uint8_t *comm_p) {
    WriteWithAlignmentResult result;

    result.left_alignment_unpadded = left_alignment_unpadded;
    result.total_write_unpadded = total_write_unpadded;
    for (size_t i = 0; i < CommitmentBytesLen; i++) {
      result.comm_p[i] = comm_p[i];
    }

    return result;
  }

  // ******************
  // TO С CASTED FUNCTIONS
  // ******************

  FFISealPreCommitOutput cRawSealPreCommitOutput(
      const RawSealPreCommitOutput &cpp_seal_pre_commit_output) {
    FFISealPreCommitOutput c_seal_pre_commit_output{};

    for (size_t i = 0; i < cpp_seal_pre_commit_output.comm_d.size(); i++) {
      c_seal_pre_commit_output.comm_d[i] = cpp_seal_pre_commit_output.comm_d[i];
    }
    for (size_t i = 0; i < cpp_seal_pre_commit_output.comm_r.size(); i++) {
      c_seal_pre_commit_output.comm_r[i] = cpp_seal_pre_commit_output.comm_r[i];
    }

    return c_seal_pre_commit_output;
  }

  FFISectorClass cSectorClass(const uint64_t sector_size,
                              const uint8_t porep_proof_partitions) {
    FFISectorClass sector_class;
    sector_class.sector_size = sector_size;
    sector_class.porep_proof_partitions = porep_proof_partitions;
    return sector_class;
  }

  FFICandidate cCandidate(const Candidate &cpp_candidate) {
    FFICandidate c_candidate;
    c_candidate.sector_id = cpp_candidate.sector_id;
    c_candidate.sector_challenge_index = cpp_candidate.sector_challenge_index;
    for (size_t i = 0; i < cpp_candidate.partial_ticket.size(); i++) {
      c_candidate.partial_ticket[i] = cpp_candidate.partial_ticket[i];
    }
    for (size_t i = 0; i < cpp_candidate.ticket.size(); i++) {
      c_candidate.ticket[i] = cpp_candidate.ticket[i];
    }
    return c_candidate;
  }

  std::vector<FFICandidate> cCandidates(
      const gsl::span<Candidate> &cpp_candidates) {
    std::vector<FFICandidate> c_candidates;
    for (const auto cpp_candidate : cpp_candidates) {
      c_candidates.push_back(cCandidate(cpp_candidate));
    }
    return c_candidates;
  }

  FFIPrivateReplicaInfo cPrivateSectorInfo(
      const PrivateSectorInfo &cpp_private_sector_info) {
    FFIPrivateReplicaInfo c_private_sector_info;

    c_private_sector_info.sector_id = cpp_private_sector_info.sector_id;

    c_private_sector_info.cache_dir_path =
        cpp_private_sector_info.cache_dir_path.data();
    c_private_sector_info.replica_path =
        cpp_private_sector_info.sealed_sector_path.data();

    for (size_t i = 0; i < cpp_private_sector_info.comm_r.size(); i++) {
      c_private_sector_info.comm_r[i] = cpp_private_sector_info.comm_r[i];
    }

    return c_private_sector_info;
  }

  FFIPublicPieceInfo *cPublicPiecesInfo(
      const gsl::span<PublicPieceInfo> &cpp_public_pieces_info) {
    FFIPublicPieceInfo *c_public_pieces_info = (FFIPublicPieceInfo *)malloc(
        cpp_public_pieces_info.size() * sizeof(FFIPublicPieceInfo));
    for (long i = 0; i < cpp_public_pieces_info.size(); i++) {
      c_public_pieces_info[i].num_bytes = cpp_public_pieces_info[i].size;
      for (size_t j = 0; j < CommitmentBytesLen; j++) {
        c_public_pieces_info[i].comm_p[j] = cpp_public_pieces_info[i].comm_p[j];
      }
    }
    return c_public_pieces_info;
  }

  // ******************
  // VERIFIED FUNCTIONS
  // ******************

  outcome::result<bool> verifyPoSt(const uint64_t sector_size,
                                   const SortedPublicSectorInfo &sector_info,
                                   const common::Blob<32> &randomness,
                                   const uint64_t challenge_count,
                                   const gsl::span<uint8_t> &proof,
                                   const gsl::span<Candidate> &winners,
                                   const common::Blob<32> &prover_id) {
    std::vector<std::array<uint8_t, CommitmentBytesLen>> sorted_comrs;
    std::vector<uint64_t> sorted_sector_ids;
    for (auto sector_info_elem : sector_info.values) {
      sorted_sector_ids.push_back(sector_info_elem.sector_id);
      sorted_comrs.push_back(sector_info_elem.comm_r);
    }

    std::vector<uint8_t> flattening;
    for (size_t i = 0; i < sorted_comrs.size(); i++) {
      for (size_t j = 0; j < CommitmentBytesLen; j++) {
        flattening.push_back(sorted_comrs[i][j]);
      }
    }

    const uint8_t(*c_randomness)[32] = &(randomness._M_elems);

    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    std::vector<FFICandidate> c_winners = cCandidates(winners);

    VerifyPoStResponse *resPtr = verify_post(sector_size,
                                             c_randomness,
                                             challenge_count,
                                             sorted_sector_ids.data(),
                                             sorted_sector_ids.size(),
                                             flattening.data(),
                                             flattening.size(),
                                             proof.data(),
                                             proof.size(),
                                             c_winners.data(),
                                             c_winners.size(),
                                             c_prover_id);

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg << "\n";
      destroy_verify_post_response(resPtr);
      return ProofsError::UNKNOWN;
    }
    bool result = resPtr->is_valid;
    destroy_verify_post_response(resPtr);
    return result;
  }

  outcome::result<bool> verifySeal(const uint64_t sector_size,
                                   const Blob<CommitmentBytesLen> &comm_r,
                                   const Blob<CommitmentBytesLen> &comm_d,
                                   const common::Blob<32> &prover_id,
                                   const common::Blob<32> &ticket,
                                   const common::Blob<32> &seed,
                                   const uint64_t sector_id,
                                   const gsl::span<uint8_t> proof) {
    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    const uint8_t(*c_ticket)[32] = &(ticket._M_elems);

    const uint8_t(*c_seed)[32] = &(seed._M_elems);

    const uint8_t(*c_comm_r)[CommitmentBytesLen] = &(comm_r._M_elems);

    const uint8_t(*c_comm_d)[CommitmentBytesLen] = &(comm_d._M_elems);

    auto resPtr = verify_seal(sector_size,
                              c_comm_r,
                              c_comm_d,
                              c_prover_id,
                              c_ticket,
                              c_seed,
                              sector_id,
                              proof.data(),
                              proof.size());

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_verify_seal_response(resPtr);

      return ProofsError::UNKNOWN;
    }

    auto result = resPtr->is_valid;
    destroy_verify_seal_response(resPtr);
    return result;
  }

  // ******************
  // GENERATED FUNCTIONS
  // ******************

  outcome::result<std::vector<Candidate>> generateCandidates(
      const uint64_t sector_size,
      const common::Blob<32> &prover_id,
      const common::Blob<32> &randomness,
      const uint64_t challenge_count,
      const SortedPrivateSectorInfo &sorted_private_sector_info) {
    const uint8_t(*c_randomness)[32] = &(randomness._M_elems);

    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    FFIPrivateReplicaInfo
        c_sorted_private_sector_info[sorted_private_sector_info.values.size()];
    for (size_t i = 0; i < sorted_private_sector_info.values.size(); i++) {
      c_sorted_private_sector_info[i] =
          cPrivateSectorInfo(sorted_private_sector_info.values[i]);
    }

    auto resPtr = generate_candidates(sector_size,
                                      c_randomness,
                                      challenge_count,
                                      c_sorted_private_sector_info,
                                      sorted_private_sector_info.values.size(),
                                      c_prover_id);

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_generate_candidates_response(resPtr);
      return ProofsError::UNKNOWN;
    }

    auto result = cppCandidates(resPtr->candidates_ptr, resPtr->candidates_len);
    destroy_generate_candidates_response(resPtr);
    return result;
  }

  outcome::result<std::vector<uint8_t>> generatePoSt(
      const uint64_t sectorSize,
      const common::Blob<32> &prover_id,
      const SortedPrivateSectorInfo &private_sector_info,
      const common::Blob<32> &randomness,
      const gsl::span<Candidate> &winners) {
    std::vector<FFICandidate> c_winners = cCandidates(winners);

    const uint8_t(*c_randomness)[32] = &(randomness._M_elems);

    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    FFIPrivateReplicaInfo
        c_private_sector_info[private_sector_info.values.size()];

    for (size_t i = 0; i < private_sector_info.values.size(); i++) {
      c_private_sector_info[i].sector_id =
          private_sector_info.values[i].sector_id;
      c_private_sector_info[i].cache_dir_path =
          private_sector_info.values[i].cache_dir_path.c_str();
      c_private_sector_info[i].replica_path =
          private_sector_info.values[i].sealed_sector_path.c_str();
      for (size_t j = 0; j < private_sector_info.values[i].comm_r.size(); j++) {
        c_private_sector_info[i].comm_r[j] =
            private_sector_info.values[i].comm_r[j];
      }
    }

    auto resPtr = generate_post(sectorSize,
                                c_randomness,
                                c_private_sector_info,
                                private_sector_info.values.size(),
                                c_winners.data(),
                                c_winners.size(),
                                c_prover_id);

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg << "\n";
      destroy_generate_post_response(resPtr);
      return ProofsError::UNKNOWN;
    }
    std::vector<uint8_t> result;
    for (size_t i = 0; i < resPtr->flattened_proofs_len; i++) {
      result.push_back(resPtr->flattened_proofs_ptr[i]);
    }
    destroy_generate_post_response(resPtr);
    return result;
  }

  outcome::result<Blob<32>> generatePieceCommitmentFromFile(
      const std::string &piece_file_path, const uint64_t piece_size) {
    int fd = open(piece_file_path.c_str(), O_RDWR);

    auto res_ptr = generate_piece_commitment(fd, piece_size);

    if (res_ptr->status_code != 0) {
      destroy_generate_piece_commitment_response(res_ptr);
      return ProofsError::UNKNOWN;
    }

    Blob<32> result;
    for (size_t i = 0; i < result.size(); i++) {
      result[i] = res_ptr->comm_p[i];
    }
    destroy_generate_piece_commitment_response(res_ptr);
    return result;
  }

  outcome::result<Blob<CommitmentBytesLen>> generateDataCommitment(
      const uint64_t sector_size, const gsl::span<PublicPieceInfo> &pieces) {
    FFIPublicPieceInfo *c_pieces = cPublicPiecesInfo(pieces);

    auto res_ptr =
        generate_data_commitment(sector_size, c_pieces, pieces.size());

    if (res_ptr->status_code != 0) {
      destroy_generate_data_commitment_response(res_ptr);
      return ProofsError::UNKNOWN;
    }

    Blob<32> result;
    for (size_t i = 0; i < result.size(); i++) {
      result[i] = res_ptr->comm_d[i];
    }
    destroy_generate_data_commitment_response(res_ptr);
    return result;
  }

  outcome::result<WriteWithoutAlignmentResult> writeWithoutAlignment(
      const std::string &piece_file_path,
      const uint64_t piece_bytes,
      const std::string &staged_sector_file_path) {
    int piece_fd = open(piece_file_path.c_str(), O_RDWR);
    int staged_sector_fd = open(staged_sector_file_path.c_str(), O_RDWR);

    auto resPtr =
        write_without_alignment(piece_fd, piece_bytes, staged_sector_fd);

    if (resPtr->status_code != 0) {
      destroy_write_without_alignment_response(resPtr);
      return ProofsError::UNKNOWN;
    }

    auto result = cppWriteWithoutAlignmentResult(resPtr->total_write_unpadded,
                                                 resPtr->comm_p);
    destroy_write_without_alignment_response(resPtr);
    return result;
  }

  outcome::result<WriteWithAlignmentResult> writeWithAlignment(
      const std::string &piece_file_path,
      const uint64_t piece_bytes,
      const std::string &staged_sector_file_path,
      const gsl::span<uint64_t> &existing_piece_sizes) {
    int piece_fd = open(piece_file_path.c_str(), O_RDWR);
    int staged_sector_fd = open(staged_sector_file_path.c_str(), O_RDWR);

    auto resPtr = write_with_alignment(piece_fd,
                                       piece_bytes,
                                       staged_sector_fd,
                                       existing_piece_sizes.data(),
                                       existing_piece_sizes.size());

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_write_with_alignment_response(resPtr);
      return ProofsError::UNKNOWN;
    }

    auto result = cppWriteWithAlignmentResult(resPtr->left_alignment_unpadded,
                                              resPtr->total_write_unpadded,
                                              resPtr->comm_p);
    destroy_write_with_alignment_response(resPtr);
    return result;
  }

  outcome::result<RawSealPreCommitOutput> sealPreCommit(
      const uint64_t sector_size,
      const uint8_t porep_proof_partitions,
      const std::string &cache_dir_path,
      const std::string &staged_sector_path,
      const std::string &sealed_sector_path,
      const uint64_t sector_id,
      const common::Blob<32> &prover_id,
      const common::Blob<32> &ticket,
      const gsl::span<PublicPieceInfo> &pieces) {
    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    const uint8_t(*c_ticket)[32] = &(ticket._M_elems);

    FFIPublicPieceInfo *c_pieces = cPublicPiecesInfo(pieces);

    auto resPtr =
        seal_pre_commit(cSectorClass(sector_size, porep_proof_partitions),
                        cache_dir_path.c_str(),
                        staged_sector_path.c_str(),
                        sealed_sector_path.c_str(),
                        sector_id,
                        c_prover_id,
                        c_ticket,
                        c_pieces,
                        pieces.size());
    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_seal_pre_commit_response(resPtr);

      return ProofsError::UNKNOWN;
    }
    auto result = cppRawSealPreCommitOutput(resPtr->seal_pre_commit_output);
    destroy_seal_pre_commit_response(resPtr);
    free(c_pieces);
    return result;
  }

  outcome::result<std::vector<uint8_t>> sealCommit(
      const uint64_t sector_size,
      const uint8_t porep_proof_partitions,
      const std::string &cache_dir_path,
      const uint64_t sector_id,
      const common::Blob<32> &prover_id,
      const common::Blob<32> &ticket,
      const common::Blob<32> &seed,
      const gsl::span<PublicPieceInfo> &pieces,
      const RawSealPreCommitOutput &rspco) {
    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    const uint8_t(*c_ticket)[32] = &(ticket._M_elems);

    const uint8_t(*c_seed)[32] = &(seed._M_elems);

    FFIPublicPieceInfo *c_pieces = cPublicPiecesInfo(pieces);

    auto resPtr = seal_commit(cSectorClass(sector_size, porep_proof_partitions),
                              cache_dir_path.c_str(),
                              sector_id,
                              c_prover_id,
                              c_ticket,
                              c_seed,
                              c_pieces,
                              pieces.size(),
                              cRawSealPreCommitOutput(rspco));

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_seal_commit_response(resPtr);

      return ProofsError::UNKNOWN;
    }

    std::vector<uint8_t> result;
    for (size_t i = 0; i < resPtr->proof_len; i++) {
      result.push_back(resPtr->proof_ptr[i]);
    }
    destroy_seal_commit_response(resPtr);
    return result;
  }

  outcome::result<void> unseal(const uint64_t sector_size,
                               const uint8_t porep_proof_partitions,
                               const std::string &cache_dir_path,
                               const std::string &sealed_sector_path,
                               const std::string &unseal_output_path,
                               const uint64_t sector_id,
                               const common::Blob<32> &prover_id,
                               const common::Blob<32> &ticket,
                               const Blob<CommitmentBytesLen> &comm_d) {
    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    const uint8_t(*c_ticket)[32] = &(ticket._M_elems);

    const uint8_t(*c_comm_d)[CommitmentBytesLen] = &(comm_d._M_elems);

    auto resPtr = unseal(cSectorClass(sector_size, porep_proof_partitions),
                         cache_dir_path.c_str(),
                         sealed_sector_path.c_str(),
                         unseal_output_path.c_str(),
                         sector_id,
                         c_prover_id,
                         c_ticket,
                         c_comm_d);

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_unseal_response(resPtr);

      return ProofsError::UNKNOWN;
    }

    return outcome::success();
  }

  outcome::result<void> unsealRange(const uint64_t sector_size,
                                    const uint8_t porep_proof_partitions,
                                    const std::string &cache_dir_path,
                                    const std::string &sealed_sector_path,
                                    const std::string &unseal_output_path,
                                    const uint64_t sector_id,
                                    const common::Blob<32> &prover_id,
                                    const common::Blob<32> &ticket,
                                    const Blob<CommitmentBytesLen> &comm_d,
                                    const uint64_t offset,
                                    const uint64_t length) {
    const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

    const uint8_t(*c_ticket)[32] = &(ticket._M_elems);

    const uint8_t(*c_comm_d)[CommitmentBytesLen] = &(comm_d._M_elems);

    auto resPtr =
        unseal_range(cSectorClass(sector_size, porep_proof_partitions),
                     cache_dir_path.c_str(),
                     sealed_sector_path.c_str(),
                     unseal_output_path.c_str(),
                     sector_id,
                     c_prover_id,
                     c_ticket,
                     c_comm_d,
                     offset,
                     length);

    if (resPtr->status_code != 0) {
      std::cerr << resPtr->error_msg;
      destroy_unseal_range_response(resPtr);

      return ProofsError::UNKNOWN;
    }

    return outcome::success();
  }

  outcome::result<fc::common::Blob<32>> finalizeTicket(
      const fc::common::Blob<32> &partial_ticket) {
    const uint8_t(*c_partial_ticket)[32] = &(partial_ticket._M_elems);

    auto res_ptr = finalize_ticket(c_partial_ticket);

    if (res_ptr->status_code != 0) {
      destroy_finalize_ticket_response(res_ptr);
      return ProofsError::UNKNOWN;
    }

    Blob<32> result;
    for (size_t i = 0; i < result.size(); i++) {
      result[i] = res_ptr->ticket[i];
    }
    destroy_finalize_ticket_response(res_ptr);
    return result;
  }

  SortedPrivateSectorInfo newSortedPrivateSectorInfo(
      const gsl::span<PrivateSectorInfo> &sector_info) {
    SortedPrivateSectorInfo sorted_sector_info;

    for (const auto &elem : sector_info) {
      sorted_sector_info.values.push_back(elem);
    }
    std::sort(sorted_sector_info.values.begin(),
              sorted_sector_info.values.end(),
              [](const PrivateSectorInfo &lhs, const PrivateSectorInfo &rhs) {
                return std::memcmp(lhs.comm_r.data(),
                                   rhs.comm_r.data(),
                                   lhs.comm_r.size())
                       < 0;
              });

    return sorted_sector_info;
  }

  fc::proofs::SortedPublicSectorInfo newSortedPublicSectorInfo(
      const gsl::span<PublicSectorInfo> &sector_info) {
    SortedPublicSectorInfo sorted_sector_info;

    for (const auto &elem : sector_info) {
      sorted_sector_info.values.push_back(elem);
    }
    std::sort(sorted_sector_info.values.begin(),
              sorted_sector_info.values.end(),
              [](const PublicSectorInfo &lhs, const PublicSectorInfo &rhs) {
                return std::memcmp(lhs.comm_r.data(),
                                   rhs.comm_r.data(),
                                   lhs.comm_r.size())
                       < 0;
              });

    return sorted_sector_info;
  }
}  // namespace fc::proofs
