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
#include <string>
#include "boost/filesystem.hpp"

namespace fc::proofs {

  boost::mutex ProofParamProvider::fetch_mutex_ = boost::mutex();

  void parseUrl(const std::string &url_str);

  auto const gateway = "https://ipfs.io/ipfs/";
  auto const param_dir = "/var/tmp/filecoin-proof-parameters";
  auto const dir_env = "FIL_PROOFS_PARAMETER_CACHE";

  namespace beast = boost::beast;  // from <boost/beast.hpp>
  namespace http = beast::http;    // from <boost/beast/http.hpp>
  namespace net = boost::asio;     // from <boost/asio.hpp>
  using tcp = net::ip::tcp;        // from <boost/asio/ip/tcp.hpp>

  outcome::result<void> doFetch(const std::string &out, paramFile info) {
    try {
      auto const host = "ipfs.io";
      auto const port = "80";
      std::string target = "/ipfs/";
      int version = 11;

      std::string custom_gateway = std::getenv("IPFS_GATEWAY");
      if (custom_gateway != "") {
        parseUrl(custom_gateway);
      }

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
    std::string dir = std::getenv(dir_env);

    if (dir == "") return param_dir;

    return dir;
  }

  outcome::result<void> ProofParamProvider::getParams(
      const std::vector<uint8_t> &param_bytes, uint64_t storage_size) {
    boost::filesystem::create_directories(
        getParamDir());  // TODO: process errors

    // TODO: Parse Bytes or JSON(change parameter)

    // TODO: For each and create tread for each download

    return outcome::success();
  }

  outcome::result<void> checkFile(const std::string &path,
                                  const paramFile &info) {
    if (std::getenv("TRUST_PARAMS") == "1") {
      // Assuming parameter files are ok. DO NOT USE IN PRODUCTION
      return outcome::success();
    }

    // TODO blake2b code file

    // TODO get sum
    // TODO get first 16 bits
    // compare with digest

    return outcome::success();
  }

  outcome::result<void> ProofParamProvider::fetch(const std::string &name,
                                                  const paramFile &info) {
    auto path = boost::filesystem::path(getParamDir()) / name;
    auto res = checkFile(path.string(), info);
    if (!res.has_error()) return outcome::success();
    // TODO: Log error

    fetch_mutex_.lock();

    auto fetch_res = doFetch(path.string(), info);

    if (fetch_res.has_error()) {
      fetch_mutex_.unlock();
      return fetch_res.error();
    }

    res = checkFile(path.string(), info);

    if (res.has_error()) {
      boost::filesystem::remove(path);
      fetch_mutex_.unlock();
      return res.error();
    }

    fetch_mutex_.unlock();

    return outcome::success();
  }
}  // namespace fc::proofs
