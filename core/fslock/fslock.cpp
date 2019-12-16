/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fslock/fslock.hpp"

#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include "fslock/fslock_error.hpp"

namespace fc::fslock {
  // TODO(artyom-yurin): Should be unlocked if process died
  outcome::result<boost::interprocess::file_lock> lock(
      const std::string &file_lock_path) {
    boost::interprocess::named_mutex mutex(boost::interprocess::open_or_create,
                                           file_lock_path.c_str());
    try {
      if (!mutex.try_lock()) return FSLockError::FILE_LOCKED;
      if (!boost::filesystem::exists(file_lock_path)) {
        boost::filesystem::ofstream os(file_lock_path);
        os.close();
        boost::interprocess::file_lock file_lock(file_lock_path.c_str());
        file_lock.lock();
        mutex.unlock();
        return std::move(file_lock);
      } else {
        boost::interprocess::file_lock file_lock(file_lock_path.c_str());
        if (!file_lock.try_lock()) {
          return FSLockError::FILE_LOCKED;
        }
        mutex.unlock();
        return std::move(file_lock);
      }
    } catch (std::exception &) {
      mutex.unlock();
      return FSLockError::UNKNOWN;
    }
  }
}  // namespace fc::fslock
