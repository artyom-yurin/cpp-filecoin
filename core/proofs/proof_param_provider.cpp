/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "proofs/proof_param_provider.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <common/outcome.hpp>
#include <cstdlib>
#include <iostream>
#include <regex>
#include <string>
#include <thread>
#include "boost/filesystem.hpp"
#include "crypto/blake2/blake2b160.hpp"
#include "proofs/proof_param_provider_error.hpp"

namespace fc::proofs {

  boost::mutex ProofParamProvider::fetch_mutex_ = boost::mutex();

  struct responseParseUrl {
    std::string host;
    std::string target;
  };

  bool hasSuffix(std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
      return (fullString.compare(fullString.length() - ending.length(),
                                 ending.length(),
                                 ending)
              == 0);
    } else {
      return false;
    }
  }

  outcome::result<responseParseUrl> parseUrl(const std::string &url_str) {
    responseParseUrl response{};

    std::smatch match;
    std::regex reg(
        "(https|http):\\/\\/([A-Za-z0-9\\-.]+)(\\/[\\/A-Za-z0-9\\-.]+)");

    if (std::regex_match(url_str, match, reg)) {
      response.host = match[2];
      response.target = match[3];
    } else {
      return outcome::success();  // ERROR
    }

    return response;
  }

  auto const default_gateway = "https://ipfs.io/ipfs/";
  auto const param_dir = "/var/tmp/filecoin-proof-parameters";
  auto const dir_env = "FIL_PROOFS_PARAMETER_CACHE";

  namespace beast = boost::beast;  // from <boost/beast.hpp>
  namespace http = beast::http;    // from <boost/beast/http.hpp>
  namespace net = boost::asio;     // from <boost/asio.hpp>
  using tcp = net::ip::tcp;        // from <boost/asio/ip/tcp.hpp>

  outcome::result<void> doFetch(const std::string &out, paramFile info) {
    try {
      std::string gateway = default_gateway;
      if (char *custom_gateway = std::getenv("IPFS_GATEWAY")) {
        gateway = custom_gateway;
      }

      OUTCOME_TRY(url, parseUrl(gateway));
      auto const host = url.host;
      auto target = url.target;
      auto const port = "80";
      int version = 11;

      boost::filesystem::fstream file;
      file.open(out,
                std::ios_base::in | std::ios_base::out | std::ios_base::app);

      boost::uintmax_t f_size = boost::filesystem::file_size(out);

      // The io_context is required for all I/O
      net::io_context ioc;

      // These objects perform our I/O
      tcp::resolver resolver(ioc);
      beast::tcp_stream stream(ioc);

      // Look up the domain name
      auto const results = resolver.resolve(host, port);

      // Make the connection on the IP address we get from a lookup
      stream.connect(results);

      if (target[target.size() - 1] != '/') {
        target += "/";
      }

      target += info.cid;

      // Set up an HTTP GET request message
      http::request<http::string_body> req{http::verb::get, target, version};
      req.set(http::field::host, host);
      req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
      std::string v = "bytes=";
      v += f_size;
      v += "-";
      req.insert("Range", v);

      // Send the HTTP request to the remote host
      http::write(stream, req);

      // This buffer is used for reading and must be persisted
      beast::flat_buffer buffer;

      // Declare a container to hold the response
      http::response<http::dynamic_body> res;

      // Receive the HTTP response
      http::read(stream, buffer, res);

      // TODO: write into file in proof dir
      // Write the message to standard out
      std::cout << res << std::endl;

      // Gracefully close the socket
      beast::error_code ec;
      stream.socket().shutdown(tcp::socket::shutdown_both, ec);

      // not_connected happens sometimes
      // so don't bother reporting it.
      //
      if (ec && ec != beast::errc::not_connected) throw beast::system_error{ec};

      // If we get here then the connection is closed gracefully
    } catch (std::exception const &e) {
      std::cerr << "Error: " << e.what() << std::endl;
      return outcome::success();  // ERROR
    }
    return outcome::success();
  }

  std::string getParamDir() {
    if (char *dir = std::getenv(dir_env)) return dir;

    return param_dir;
  }

  outcome::result<void> ProofParamProvider::getParams(
      const std::vector<paramFile> &param_files, uint64_t storage_size) {
    try {
      boost::filesystem::create_directories(getParamDir());
    } catch (const std::exception &e) {
      std::cerr << "Error: " << e.what() << "\n";
      return outcome::success();  // ERROR
    }
    std::vector<std::thread> threads;
    for (const auto param_file : param_files) {
      if (param_file.sector_size != storage_size
          && hasSuffix(param_file.name, ".params")) {
        continue;
      }

      std::thread t(fetch, param_file);

      threads.push_back(std::move(t));
    }

    for (auto &th : threads) {
      th.join();
    }

    return outcome::success();
  }

  outcome::result<void> ProofParamProvider::checkFile(const std::string &path,
                                                      const paramFile &info) {
    char *res = std::getenv("TRUST_PARAMS");
    if (res && std::strcmp(res, "1") == 0) {
      // Assuming parameter files are ok. DO NOT USE IN PRODUCTION
      return outcome::success();
    }

    std::ifstream ifs(path, std::ios::binary);

    if (!ifs.is_open()) return ProofParamProviderError::FILE_DOES_NOT_OPEN;

    // read file
    std::vector<uint8_t> file_bytes = {};

    uint8_t ch = ifs.get();
    while (!ifs.eof()) {
      file_bytes.push_back(ch);
      ch = ifs.get();
    }

    gsl::span<uint8_t> content(file_bytes.data(), file_bytes.size());

    OUTCOME_TRY(sum, crypto::blake2b::blake2b_512(content));

    if (common::hex_lower(gsl::span<uint8_t>(sum.data(), 16)) != info.digest) {
      return ProofParamProviderError::CHECKSUM_MISMATCH;
    }

    return outcome::success();
  }

  void ProofParamProvider::fetch(const paramFile &info) {
    auto path = boost::filesystem::path(getParamDir())
                / boost::filesystem::path(info.name);
    auto res = checkFile(path.string(), info);
    if (!res.has_error()) {
      return;  // All is right
    } else if (!boost::filesystem::exists(path)) {
      std::cerr << "Error\n";
      // TODO: more concrete
    }

    fetch_mutex_.lock();

    auto fetch_res = doFetch(path.string(), info);

    if (fetch_res.has_error()) {
      // TODO write error
      fetch_mutex_.unlock();
      return;
    }

    res = checkFile(path.string(), info);

    if (res.has_error()) {
      // TODO write error
      boost::filesystem::remove(path);
      fetch_mutex_.unlock();
      return;
    }

    fetch_mutex_.unlock();

    return;
  }
}  // namespace fc::proofs
