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

fc::proofs::Candidate cppCandidate(const FFICandidate *c_candidate) {
  fc::proofs::Candidate candidate;
  candidate.sector_id = c_candidate->sector_id;
  candidate.sector_challenge_index = c_candidate->sector_challenge_index;
  for (size_t i = 0; i < candidate.ticket[32]; i++) {
    candidate.ticket[i] = c_candidate->ticket[i];
  }
  for (size_t i = 0; i < candidate.partial_ticket[32]; i++) {
    candidate.partial_ticket[i] = c_candidate->partial_ticket[i];
  }
  return candidate;
}

std::vector<fc::proofs::Candidate> cppCandidates(
    const FFICandidate *candidates_ptr, size_t size) {
  std::vector<fc::proofs::Candidate> cpp_candidates;
  if (candidates_ptr == nullptr || size == 0) {
    return cpp_candidates;
  }

  const FFICandidate *current_c_candidate = candidates_ptr;
  for (size_t i = 0; i < size; i++) {
    cpp_candidates.push_back(cppCandidate(current_c_candidate++));
  }

  return cpp_candidates;
}

FFICandidate cCandidate(const fc::proofs::Candidate &cpp_candidate) {
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
    const std::vector<fc::proofs::Candidate> &cpp_candidates) {
  std::vector<FFICandidate> c_candidates;
  for (const auto cpp_candidate : cpp_candidates) {
    c_candidates.push_back(cCandidate(cpp_candidate));
  }
  return c_candidates;
}

fc::outcome::result<std::vector<fc::proofs::Candidate>>
fc::proofs::generateCandidates(
    const uint64_t sector_size,
    const fc::common::Blob<32> &prover_id,
    const fc::common::Blob<32> &randomness,
    const uint64_t challenge_count,
    const fc::proofs::SortedPrivateSectorInfo &sorted_private_sector_info) {
  const uint8_t(*c_randomness)[32] = &(randomness._M_elems);

  const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

  std::vector<FFIPrivateReplicaInfo> c_sorted_private_sector_info;
  for (const auto private_sector_info : sorted_private_sector_info.f) {
    FFIPrivateReplicaInfo c_private_sector_info;
    c_private_sector_info.sector_id = private_sector_info.sector_id;
    c_private_sector_info.cache_dir_path =
        private_sector_info.cache_dir_path.data();
    c_private_sector_info.replica_path =
        private_sector_info.sealed_sector_path.data();
    for (size_t i = 0; i < private_sector_info.comm_r.size(); i++) {
      c_private_sector_info.comm_r[i] = private_sector_info.comm_r[i];
    }
    c_sorted_private_sector_info.push_back(c_private_sector_info);
  }

  auto resPtr = generate_candidates(sector_size,
                                    c_randomness,
                                    challenge_count,
                                    c_sorted_private_sector_info.data(),
                                    c_sorted_private_sector_info.size(),
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

FFIPrivateReplicaInfo cPrivateSectorInfo(
    const fc::proofs::PrivateSectorInfo &cpp_private_sector_info) {
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

std::vector<FFIPrivateReplicaInfo> cSortedPrivateSectorInfo(
    const fc::proofs::SortedPrivateSectorInfo &cpp_sorted_private_sector_info) {
  std::vector<FFIPrivateReplicaInfo> c_sorted_private_sector_info;
  for (auto cpp_private_sector_info : cpp_sorted_private_sector_info.f) {
    c_sorted_private_sector_info.push_back(
        cPrivateSectorInfo(cpp_private_sector_info));
  }
  return c_sorted_private_sector_info;
}

FFIPublicPieceInfo *cPublicPiecesInfo(
    const std::vector<fc::proofs::PublicPieceInfo> &cpp_public_pieces_info) {
  FFIPublicPieceInfo *c_public_pieces_info = (FFIPublicPieceInfo *)malloc(
      cpp_public_pieces_info.size() * sizeof(FFIPublicPieceInfo));
  for (size_t i = 0; i < cpp_public_pieces_info.size(); i++) {
    c_public_pieces_info[i].num_bytes = cpp_public_pieces_info[i].size;
    for (size_t j = 0; j < cpp_public_pieces_info[i].comm_p.size(); j++) {
      c_public_pieces_info[i].comm_p[j] = cpp_public_pieces_info[i].comm_p[j];
    }
  }
  return c_public_pieces_info;
}

fc::outcome::result<std::vector<uint8_t>> fc::proofs::generatePoSt(
    const uint64_t sectorSize,
    const fc::common::Blob<32> &prover_id,
    const fc::proofs::SortedPrivateSectorInfo &private_sector_info,
    const fc::common::Blob<32> &randomness,
    const std::vector<Candidate> &winners) {
  std::vector<FFICandidate> c_winners = cCandidates(winners);

  const uint8_t(*c_randomness)[32] = &(randomness._M_elems);

  const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

  std::vector<FFIPrivateReplicaInfo> c_private_sector_info =
      cSortedPrivateSectorInfo(private_sector_info);

  auto resPtr = generate_post(sectorSize,
                              c_randomness,
                              c_private_sector_info.data(),
                              c_private_sector_info.size(),
                              c_winners.data(),
                              c_winners.size(),
                              c_prover_id);

  if (resPtr->status_code != 0) {
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

fc::outcome::result<bool> fc::proofs::verifyPoSt(
    const uint64_t sector_size,
    const fc::proofs::SortedPublicSectorInfo &sector_info,
    const fc::common::Blob<32> &randomness,
    const uint64_t challenge_count,
    const std::vector<uint8_t> &proof,
    const std::vector<Candidate> &winners,
    const fc::common::Blob<32> &prover_id) {
  std::vector<std::array<uint8_t, CommitmentBytesLen>> sorted_comrs;
  std::vector<uint64_t> sorted_sector_ids;
  for (auto sector_info_elem : sector_info.f) {
    sorted_sector_ids.push_back(sector_info_elem.sector_id);
    sorted_comrs.push_back(sector_info_elem.comm_r);
  }

  uint8_t flattening[CommitmentBytesLen * sorted_comrs.size()];
  for (size_t i = 0; i < sorted_comrs.size(); i++) {
    for (size_t j = 0; j < sorted_comrs[i].size(); j++) {
      flattening[i * j] = sorted_comrs[i][j];
    }
  }

  const uint8_t(*c_randomness)[32] = &(randomness._M_elems);

  const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

  std::vector<FFICandidate> c_winners = cCandidates(winners);

  VerifyPoStResponse *resPtr =
      verify_post(sector_size,
                  c_randomness,
                  challenge_count,
                  sorted_sector_ids.data(),
                  sorted_sector_ids.size(),
                  flattening,
                  CommitmentBytesLen * sorted_comrs.size(),
                  proof.data(),
                  proof.size(),
                  c_winners.data(),
                  c_winners.size(),
                  c_prover_id);

  int status_code = resPtr->status_code;
  if (status_code != 0) {
    destroy_verify_post_response(resPtr);
    return ProofsError::UNKNOWN;
  }
  bool result = resPtr->is_valid;
  destroy_verify_post_response(resPtr);
  return result;
}
fc::outcome::result<Blob<32>> fc::proofs::generatePieceCommitmentFromFile(
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

FFISectorClass cSectorClass(const uint64_t sector_size,
                            const uint8_t porep_proof_partitions) {
  FFISectorClass sector_class;
  sector_class.sector_size = sector_size;
  sector_class.porep_proof_partitions = porep_proof_partitions;
  return sector_class;
}

fc::proofs::RawSealPreCommitOutput cppRawSealPreCommitOutput(
    const FFISealPreCommitOutput &c_seal_pre_commit_output) {
  fc::proofs::RawSealPreCommitOutput cpp_seal_pre_commit_output;

  for (size_t i = 0; i < cpp_seal_pre_commit_output.comm_d.size(); i++) {
    cpp_seal_pre_commit_output.comm_d[i] = c_seal_pre_commit_output.comm_d[i];
  }
  for (size_t i = 0; i < cpp_seal_pre_commit_output.comm_r.size(); i++) {
    cpp_seal_pre_commit_output.comm_r[i] = c_seal_pre_commit_output.comm_r[i];
  }
  return cpp_seal_pre_commit_output;
}

FFISealPreCommitOutput cRawSealPreCommitOutput(
    const fc::proofs::RawSealPreCommitOutput &cpp_seal_pre_commit_output) {
  FFISealPreCommitOutput c_seal_pre_commit_output{};

  for (size_t i = 0; i < cpp_seal_pre_commit_output.comm_d.size(); i++) {
    c_seal_pre_commit_output.comm_d[i] = cpp_seal_pre_commit_output.comm_d[i];
  }
  for (size_t i = 0; i < cpp_seal_pre_commit_output.comm_r.size(); i++) {
    c_seal_pre_commit_output.comm_r[i] = cpp_seal_pre_commit_output.comm_r[i];
  }

  return c_seal_pre_commit_output;
}

fc::proofs::WriteWithoutAlignmentResult cppWriteWithoutAlignmentResult(
    const uint64_t total_write_unpadded, const uint8_t *comm_p) {
  fc::proofs::WriteWithoutAlignmentResult result;
  result.total_write_unpadded = total_write_unpadded;
  for (size_t i = 0; i < result.comm_p.size(); i++) {
    result.comm_p[i] = comm_p[i];
  }
  return result;
}

fc::outcome::result<fc::proofs::WriteWithoutAlignmentResult>
fc::proofs::writeWithoutAlignment(const std::string &piece_file_path,
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

fc::proofs::WriteWithAlignmentResult cppWriteWithAlignmentResult(
    const uint64_t left_alignment_unpadded,
    const uint64_t total_write_unpadded,
    const uint8_t *comm_p) {
  fc::proofs::WriteWithAlignmentResult result;
  result.left_alignment_unpadded = left_alignment_unpadded;
  result.total_write_unpadded = total_write_unpadded;
  for (size_t i = 0; i < result.comm_p.size(); i++) {
    result.comm_p[i] = comm_p[i];
  }
  return result;
}

fc::outcome::result<fc::proofs::WriteWithAlignmentResult>
fc::proofs::writeWithAlignment(
    const std::string &piece_file_path,
    const uint64_t piece_bytes,
    const std::string &staged_sector_file_path,
    const std::vector<uint64_t> &existing_piece_sizes) {
  int piece_fd = open(piece_file_path.c_str(), O_RDWR);
  int staged_sector_fd = open(staged_sector_file_path.c_str(), O_RDWR);

  uint64_t c_existing_piece_sizes[existing_piece_sizes.size()];

  for (size_t i = 0; i < existing_piece_sizes.size(); i++) {
    c_existing_piece_sizes[i] = existing_piece_sizes[i];
  }

  auto resPtr = write_with_alignment(piece_fd,
                                     piece_bytes,
                                     staged_sector_fd,
                                     c_existing_piece_sizes,
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

fc::outcome::result<fc::proofs::RawSealPreCommitOutput>
fc::proofs::sealPreCommit(const uint64_t sector_size,
                          const uint8_t porep_proof_partitions,
                          const std::string &cache_dir_path,
                          const std::string &staged_sector_path,
                          const std::string &sealed_sector_path,
                          const uint64_t sector_id,
                          const fc::common::Blob<32> &prover_id,
                          const fc::common::Blob<32> &ticket,
                          const std::vector<PublicPieceInfo> &pieces) {
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
  return result;
}

fc::outcome::result<std::vector<uint8_t>> fc::proofs::sealCommit(
    const uint64_t sector_size,
    const uint8_t porep_proof_partitions,
    const std::string &cache_dir_path,
    const uint64_t sector_id,
    const fc::common::Blob<32> &prover_id,
    const fc::common::Blob<32> &ticket,
    const fc::common::Blob<32> &seed,
    const std::vector<PublicPieceInfo> &pieces,
    const fc::proofs::RawSealPreCommitOutput &rspco) {
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

fc::outcome::result<bool> fc::proofs::verifySeal(
    const uint64_t sector_size,
    const Blob<CommitmentBytesLen> &comm_r,
    const Blob<CommitmentBytesLen> &comm_d,
    const fc::common::Blob<32> &prover_id,
    const fc::common::Blob<32> &ticket,
    const fc::common::Blob<32> &seed,
    const uint64_t sector_id,
    const std::vector<uint8_t> proof) {
  const uint8_t(*c_prover_id)[32] = &(prover_id._M_elems);

  const uint8_t(*c_ticket)[32] = &(ticket._M_elems);

  const uint8_t(*c_seed)[32] = &(seed._M_elems);

  const uint8_t(*c_comm_r)[32] = &(comm_r._M_elems);

  const uint8_t(*c_comm_d)[32] = &(comm_d._M_elems);

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
