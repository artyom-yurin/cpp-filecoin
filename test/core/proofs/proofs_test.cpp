/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "proofs/proofs.hpp"

#include <gtest/gtest.h>
#include <random>
#include "proofs/proof_param_provider.hpp"
#include "proofs/proofs_error.hpp"
#include "storage/filestore/impl/filesystem/filesystem_file.hpp"
#include "testutil/outcome.hpp"
#include "testutil/storage/base_fs_test.hpp"

using fc::storage::filestore::File;
using fc::storage::filestore::FileSystemFile;
using fc::storage::filestore::Path;

class ProofsTest : public test::BaseFS_Test {
 public:
  ProofsTest() : test::BaseFS_Test("fc_proofs_test") {
    auto res = fc::proofs::ProofParamProvider::readJson(
        "/tmp/filecoin-proof-parameters/parameters.json");
    if (!res.has_error()) {
      params = std::move(res.value());
    }
  }

 protected:
  std::vector<fc::proofs::ParamFile> params;
};

TEST_F(ProofsTest, ValidPoSt) {
  uint64_t challenge_count = 2;
  uint8_t porep_proof_partitions = 10;
  fc::common::Blob<32> prover_id{{6, 7, 8}};
  fc::common::Blob<32> randomness{{9, 9, 9}};
  fc::common::Blob<32> ticket{{5, 4, 2}};
  fc::common::Blob<32> seed{{7, 4, 2}};
  uint64_t sector_size = 1024;
  uint64_t sector_id = 42;
  EXPECT_OUTCOME_TRUE_1(
      fc::proofs::ProofParamProvider::getParams(params, sector_size));

  Path metadata_dir = boost::filesystem::unique_path(
                          fs::canonical(base_path).append("%%%%%-metadata"))
                          .string();
  boost::filesystem::create_directory(metadata_dir);
  Path sealed_sectors_dir =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-sealed-sectors"))
          .string();
  boost::filesystem::create_directory(sealed_sectors_dir);
  Path staged_sectors_dir =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-staged-sectors"))
          .string();
  boost::filesystem::create_directory(staged_sectors_dir);
  Path sector_cache_root_dir =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-sector-cache-root-dir"))
          .string();
  boost::filesystem::create_directory(sector_cache_root_dir);
  Path sector_cache_dir_path =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-sector-cache-dir"))
          .string();
  boost::filesystem::create_directory(sector_cache_dir_path);

  Path staged_sector_file =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-staged-sector-file"))
          .string();
  boost::filesystem::ofstream(staged_sector_file).close();

  Path sealed_sector_file =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-sealed-sector-file"))
          .string();
  boost::filesystem::ofstream(sealed_sector_file).close();

  Path unseal_output_file_a =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-unseal-output-file-a"))
          .string();
  boost::filesystem::ofstream(unseal_output_file_a).close();

  Path unseal_output_file_b =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-unseal-output-file-b"))
          .string();
  boost::filesystem::ofstream(unseal_output_file_b).close();

  Path unseal_output_file_c =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-unseal-output-file-c"))
          .string();
  boost::filesystem::ofstream(unseal_output_file_c).close();

  Path unseal_output_file_d =
      boost::filesystem::unique_path(
          fs::canonical(base_path).append("%%%%%-unseal-output-file-d"))
          .string();
  boost::filesystem::ofstream(unseal_output_file_d).close();

  fc::common::Blob<1016> some_bytes;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint8_t> dis(0, 255);
  for (size_t i = 0; i < some_bytes.size(); i++) {
    some_bytes[i] = dis(gen);
  }

  auto path_model = fs::canonical(base_path).append("%%%%%");
  Path piece_file_a_path = boost::filesystem::unique_path(path_model).string();
  boost::filesystem::ofstream piece_file_a(piece_file_a_path);

  int piece_commitment_a_size = 127;
  for (int i = 0; i < piece_commitment_a_size; i++) {
    piece_file_a << some_bytes[i];
  }
  piece_file_a.close();

  Path piece_file_b_path = boost::filesystem::unique_path(path_model).string();
  boost::filesystem::ofstream piece_file_b(piece_file_b_path);

  int piece_commitment_b_size = 508;
  for (int i = 0; i < piece_commitment_b_size; i++) {
    piece_file_b << some_bytes[i];
  }
  piece_file_b.close();

  std::vector<fc::proofs::PublicPieceInfo> public_pieces;

  fc::proofs::PublicPieceInfo pA;
  pA.size = piece_commitment_a_size;
  EXPECT_OUTCOME_TRUE(piece_commitment_a,
                      fc::proofs::generatePieceCommitmentFromFile(
                          piece_file_a_path, piece_commitment_a_size));
  pA.comm_p = piece_commitment_a;

  EXPECT_OUTCOME_TRUE(
      resA,
      fc::proofs::writeWithoutAlignment(
          piece_file_a_path, piece_commitment_a_size, staged_sector_file));
  ASSERT_EQ(resA.total_write_unpadded, piece_commitment_a_size);

  EXPECT_OUTCOME_TRUE(resB,
                      fc::proofs::writeWithAlignment(piece_file_b_path,
                                                     piece_commitment_b_size,
                                                     staged_sector_file,
                                                     {127}));
  ASSERT_EQ(resB.left_alignment_unpadded,
            piece_commitment_b_size - piece_commitment_a_size);

  fc::proofs::PublicPieceInfo pB;
  pB.size = piece_commitment_b_size;
  EXPECT_OUTCOME_TRUE(piece_commitment_b,
                      fc::proofs::generatePieceCommitmentFromFile(
                          piece_file_b_path, piece_commitment_b_size));
  pB.comm_p = piece_commitment_b;

  public_pieces.push_back(pA);
  public_pieces.push_back(pB);

  // pre-commit the sector
  EXPECT_OUTCOME_TRUE(output,
                      fc::proofs::sealPreCommit(sector_size,
                                                porep_proof_partitions,
                                                sector_cache_dir_path,
                                                staged_sector_file,
                                                sealed_sector_file,
                                                sector_id,
                                                prover_id,
                                                ticket,
                                                public_pieces));

  // commit the sector
  EXPECT_OUTCOME_TRUE(proof,
                      fc::proofs::sealCommit(sector_size,
                                             porep_proof_partitions,
                                             sector_cache_dir_path,
                                             sector_id,
                                             prover_id,
                                             ticket,
                                             seed,
                                             public_pieces,
                                             output));

  EXPECT_OUTCOME_TRUE(isValid,
                      fc::proofs::verifySeal(sector_size,
                                             output.comm_r,
                                             output.comm_d,
                                             prover_id,
                                             ticket,
                                             seed,
                                             sector_id,
                                             proof));
  ASSERT_TRUE(isValid);

  fc::proofs::SortedPublicSectorInfo public_info;
  fc::proofs::PublicSectorInfo public_sector_info;
  public_sector_info.sector_id = sector_id;
  public_sector_info.comm_r = output.comm_r;
  public_info.f.push_back(public_sector_info);

  fc::proofs::SortedPrivateSectorInfo private_info;
  fc::proofs::PrivateSectorInfo private_sector_info;
  private_sector_info.sector_id = sector_id;
  private_sector_info.comm_r = output.comm_r;
  private_sector_info.cache_dir_path = sector_cache_dir_path;
  private_sector_info.sealed_sector_path = sealed_sector_file;
  private_info.f.push_back(private_sector_info);

  EXPECT_OUTCOME_TRUE(
      candidates,
      fc::proofs::generateCandidates(
          sector_size, prover_id, randomness, challenge_count, private_info));
  EXPECT_OUTCOME_TRUE(
      proof_a,
      fc::proofs::generatePoSt(
          sector_size, prover_id, private_info, randomness, candidates))
  EXPECT_OUTCOME_TRUE(res,
                      fc::proofs::verifyPoSt(sector_size,
                                             public_info,
                                             randomness,
                                             challenge_count,
                                             proof_a,
                                             candidates,
                                             prover_id));
  ASSERT_TRUE(res) << "VerifyPoSt rejected the (standalone) proof as invalid";
}
