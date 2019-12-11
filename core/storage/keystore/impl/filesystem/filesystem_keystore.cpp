/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "filesystem_keystore.hpp"

#include "storage/filestore/filestore_error.hpp"
#include "storage/filestore/impl/filesystem/filesystem_filestore.hpp"

using fc::storage::filestore::FileStoreError;
using fc::storage::filestore::FileSystemFileStore;
using fc::storage::filestore::Path;
using fc::storage::keystore::FileSystemKeyStore;
using fc::storage::keystore::KeyStore;
using fc::storage::keystore::KeyStoreError;

FileSystemKeyStore::FileSystemKeyStore(
    Path path,
    std::shared_ptr<BlsProvider> blsProvider,
    std::shared_ptr<Secp256k1Provider> secp256K1Provider)
    : KeyStore(std::move(blsProvider), std::move(secp256K1Provider)),
      keystore_path_(std::move(path)),
      filestore_(std::make_shared<FileSystemFileStore>()) {}

fc::outcome::result<bool> FileSystemKeyStore::Has(
    const Address &address) noexcept {
  OUTCOME_TRY(path, AddressToPath(address));
  OUTCOME_TRY(exists, filestore_->exists(path));
  return exists;
}

fc::outcome::result<void> FileSystemKeyStore::Put(
    Address address, typename KeyStore::TPrivateKey key) noexcept {
  OUTCOME_TRY(exists, Has(address));
  if (exists) return KeyStoreError::ALREADY_EXISTS;
  OUTCOME_TRY(path, AddressToPath(address));
  OUTCOME_TRY(file, filestore_->create(path));

  // TODO(a.chernyshov)wait for address implementation
  // https://github.com/filecoin-project/cpp-filecoin/pull/16
  if (address == 1) {
    auto bls_private_key = boost::get<BlsPrivateKey>(key);
    OUTCOME_TRY(write_size, file->write(0, bls_private_key));
    if (write_size != bls_private_key.size()) {
      return KeyStoreError::CANNOT_STORE;
    }
    return fc::outcome::success();
  }
  if (address == 2) {
    auto secp256k1_private_key = boost::get<Secp256k1PrivateKey>(key);
    OUTCOME_TRY(write_size, file->write(0, secp256k1_private_key));
    if (write_size != secp256k1_private_key.size()) {
      return KeyStoreError::CANNOT_STORE;
    }
    return fc::outcome::success();
  }

  return KeyStoreError::WRONG_ADDRESS;
}

fc::outcome::result<void> FileSystemKeyStore::Remove(
    const Address &address) noexcept {
  OUTCOME_TRY(found, Has(address));
  if (!found) return KeyStoreError::NOT_FOUND;
  OUTCOME_TRY(path, AddressToPath(address));
  OUTCOME_TRY(filestore_->remove(path));
  return fc::outcome::success();
}

fc::outcome::result<std::vector<typename FileSystemKeyStore::Address>>
FileSystemKeyStore::List() noexcept {
  OUTCOME_TRY(files, filestore_->list(keystore_path_));
  std::vector<Address> res(files.size());
  std::transform(
      files.begin(), files.end(), res.begin(), [this](const Path &file) {
        std::size_t from = file.find_last_of(filestore::DELIMITER) + 1;
        std::size_t to = file.rfind(this->kPrivateKeyExtension);

        // TODO(a.chernyshov)wait for address implementation
        // https://github.com/filecoin-project/cpp-filecoin/pull/16
        return std::stoi(file.substr(from, to - from));
      });

  return std::move(res);
}

fc::outcome::result<typename KeyStore::TPrivateKey> FileSystemKeyStore::Get(
    const typename FileSystemKeyStore::Address &address) noexcept {
  OUTCOME_TRY(found, Has(address));
  if (!found) return KeyStoreError::NOT_FOUND;
  OUTCOME_TRY(path, AddressToPath(address));
  OUTCOME_TRY(file, filestore_->open(path));

  // TODO(a.chernyshov) wait for address implementation
  // https://github.com/filecoin-project/cpp-filecoin/pull/16
  if (address == 1) {
    BlsPrivateKey private_key{};
    OUTCOME_TRY(read_size, file->read(0, private_key));
    if (read_size != private_key.size()) {
      return KeyStoreError::CANNOT_READ;
    }

    return private_key;
  }
  if (address == 2) {
    Secp256k1PrivateKey private_key{};
    OUTCOME_TRY(read_size, file->read(0, private_key));
    if (read_size != private_key.size()) {
      return KeyStoreError::CANNOT_READ;
    }

    return private_key;
  }

  return KeyStoreError::WRONG_ADDRESS;
}

fc::outcome::result<Path> FileSystemKeyStore::AddressToPath(
    const Address &address) const noexcept {
  // TODO(a.chernyshov) wait for address implementation
  // https://github.com/filecoin-project/cpp-filecoin/pull/16
  std::stringstream ss;
  ss << address;
  Path res =
      keystore_path_ + filestore::DELIMITER + ss.str() + kPrivateKeyExtension;

  return res;
}
