// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <boost/intrusive_ptr.hpp>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "common/ceph_context.h"
#include "common/ceph_json.h"
#include "common/dout.h"
#include "rgw_sts_ec_jwk.h"

// The keys below are generated with the same OpenSSL 1.1 EC_KEY and RSA APIs
// that jwt.h uses, which OpenSSL 3 deprecates.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

using namespace std::chrono_literals;
using jwt::helper::decode_base64url_unpadded;
using rgw::auth::sts::detail::ec_jwk_curve_algorithm;
using rgw::auth::sts::detail::validate_signature_using_ec_jwk;

namespace {

boost::intrusive_ptr<CephContext> cct{new CephContext(CEPH_ENTITY_TYPE_CLIENT), false};
const NoDoutPrefix dpp{cct.get(), ceph_subsys_rgw};

// A JWKS from SPIRE's OIDC discovery provider during a key rotation: P-384,
// "alg" set, no "use" and no "x5c". The token is signed by keys[1], with Go's
// crypto/ecdsa rather than jwt-cpp, and expires in 2100.
const std::string spire_jwks = R"({"keys":[)"
  R"({"alg":"ES384","crv":"P-384","kid":"tOjZnN8kAk5womMAkmJgwF5hpI1Fd1um","kty":"EC","x":"IaQZnt0UjPLJfKvrRbSx9gIWg85_aciacSM-7_jMlvrGV-euRkQZ3iVJKX_nzyEF","y":"SazBPP6ZHY9wePNMr-249120s_B0QOXjsvCGjlFiHsxRKBY1754pR2cWQ3_-VW2Y"},)"
  R"({"alg":"ES384","crv":"P-384","kid":"eL0RsziBAgYKYzNw5iOjgnSEexm34JOw","kty":"EC","x":"X2OAirFdOjHHkuIkljrlaM47TEQA_GGh8IznxG-5DqnnNK4kg29aI8Ot8NVn7h9I","y":"bnAwpu2BKOlEyvXl2Y0YmpCHb_HVfQnUmwQe07tiLNN4mBdzc1J5a-yFZQF4dKlV"},)"
  R"({"alg":"ES384","crv":"P-384","kid":"G8UCMCeVSlRs5KL3H0iJSQel7vFHTVCI","kty":"EC","x":"V6izyHUy_6cJz22cx66hCltKP2hWe0tjW6uVvcDhFJiX0kQMWgpPuI7wVhoWxMHx","y":"DNdXEGIUJC8ofj09lERTk0ZGaLYvQiQjNbYNsK1JscvDS2mFKIBxJUVYsp0VZSYC"})"
  R"(]})";
const std::string spire_token =
  "eyJhbGciOiJFUzM4NCIsImtpZCI6ImVMMFJzemlCQWdZS1l6Tnc1aU9qZ25TRWV4bTM0Sk93IiwidHlwIjoiSldUIn0"
  ".eyJhdWQiOlsic3RzIl0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzk1NzM3NjAwLCJpc3MiOiJodHRwczovL29pZGMtZGlzY292ZXJ5LmV4YW1wbGUub3JnIiwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvbnMvZGVmYXVsdC9zYS9hcHAifQ"
  ".hXWI30nmUP7gAKwZdfNYmqtoxrc3OU7eyWeanp5FVXHA7vOUopvNOg8gDwsYuFMgCrELLkZioFhO0G8MEjoS-Cy2i4KhlVt_AZGlCsr_8KBtVJWMgYUa8fsTfgZD_TN3";

std::string b64url(const std::string& bin)
{
  auto s = jwt::base::encode<jwt::alphabet::base64url>(bin);
  return s.substr(0, s.find(jwt::alphabet::base64url::fill()));
}

std::string bio_string(BIO* bio)
{
  char* data = nullptr;
  const long len = BIO_get_mem_data(bio, &data);
  return std::string(data, len);
}

std::string bn_bin(const BIGNUM* bn, size_t len)
{
  std::string out(len, '\0');
  BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(out.data()), len);
  return out;
}

struct ec_key {
  std::string crv;
  std::string alg;
  std::string private_pem;
  std::string x; // base64url
  std::string y; // base64url
};

ec_key make_ec_key(const std::string& crv)
{
  int nid;
  if (crv == "P-256") {
    nid = NID_X9_62_prime256v1;
  } else if (crv == "P-384") {
    nid = NID_secp384r1;
  } else if (crv == "P-521") {
    nid = NID_secp521r1;
  } else {
    throw std::invalid_argument("unknown curve " + crv);
  }
  std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(EC_KEY_new_by_curve_name(nid), EC_KEY_free);
  std::unique_ptr<BIO, decltype(&BIO_free_all)> priv(BIO_new(BIO_s_mem()), BIO_free_all);
  if (!key || EC_KEY_generate_key(key.get()) != 1 ||
      PEM_write_bio_ECPrivateKey(priv.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    throw std::runtime_error("failed to generate EC key");
  }
  const EC_GROUP* group = EC_KEY_get0_group(key.get());
  const size_t len = (EC_GROUP_get_degree(group) + 7) / 8;
  std::unique_ptr<BIGNUM, decltype(&BN_free)> x(BN_new(), BN_free);
  std::unique_ptr<BIGNUM, decltype(&BN_free)> y(BN_new(), BN_free);
  if (EC_POINT_get_affine_coordinates_GFp(group, EC_KEY_get0_public_key(key.get()),
                                          x.get(), y.get(), nullptr) != 1) {
    throw std::runtime_error("EC_POINT_get_affine_coordinates failed");
  }
  return {crv, std::string(ec_jwk_curve_algorithm(crv)), bio_string(priv.get()),
          b64url(bn_bin(x.get(), len)), b64url(bn_bin(y.get(), len))};
}

struct rsa_key {
  std::string private_pem;
  std::string n; // base64url
  std::string e; // base64url
};

// RSA key generation is slow, so the tests share one key.
const rsa_key& shared_rsa_key()
{
  static const rsa_key k = [] {
    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> exponent(BN_new(), BN_free);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> priv(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!rsa || !exponent || BN_set_word(exponent.get(), RSA_F4) != 1 ||
        RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr) != 1 ||
        PEM_write_bio_RSAPrivateKey(priv.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
      throw std::runtime_error("failed to generate RSA key");
    }
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa.get(), &n, &e, nullptr);
    return rsa_key{bio_string(priv.get()), b64url(bn_bin(n, BN_num_bytes(n))),
                   b64url(bn_bin(e, BN_num_bytes(e)))};
  }();
  return k;
}

jwt::builder token_builder(std::chrono::seconds ttl)
{
  const auto now = std::chrono::system_clock::now();
  return jwt::create()
      .set_type("JWT")
      .set_issuer("https://oidc-discovery.example.org")
      .set_subject("spiffe://example.org/ns/default/sa/app")
      .set_audience("sts")
      .set_issued_at(now - 1min)
      .set_expires_at(now + ttl);
}

std::string sign(const ec_key& k, std::chrono::seconds ttl = 1h)
{
  auto builder = token_builder(ttl);
  if (k.alg == "ES256") {
    return builder.sign(jwt::algorithm::es256{"", k.private_pem});
  }
  if (k.alg == "ES384") {
    return builder.sign(jwt::algorithm::es384{"", k.private_pem});
  }
  return builder.sign(jwt::algorithm::es512{"", k.private_pem});
}

std::string sign(const rsa_key& k)
{
  return token_builder(1h).sign(jwt::algorithm::rs256{"", k.private_pem});
}

std::string with_payload(const std::string& token, const std::string& payload)
{
  const auto d = jwt::decode(token);
  return d.get_header_base64() + "." + b64url(payload) + "." + d.get_signature_base64();
}

std::string with_signature(const std::string& token, const std::string& sig)
{
  const auto d = jwt::decode(token);
  return d.get_header_base64() + "." + d.get_payload_base64() + "." + b64url(sig);
}

// JWK members, in order. Every test value is a JSON string.
using fields = std::vector<std::pair<std::string, std::string>>;

fields ec_jwk(const ec_key& k)
{
  return {{"kty", "EC"}, {"crv", k.crv}, {"alg", k.alg}, {"x", k.x}, {"y", k.y}};
}

fields rsa_jwk(const rsa_key& k)
{
  return {{"kty", "RSA"}, {"alg", "RS256"}, {"n", k.n}, {"e", k.e}};
}

fields with(fields f, const std::string& name, const std::string& value)
{
  for (auto& [n, v] : f) {
    if (n == name) {
      v = value;
      return f;
    }
  }
  f.emplace_back(name, value);
  return f;
}

fields without(fields f, const std::string& name)
{
  f.erase(std::remove_if(f.begin(), f.end(),
                         [&](const auto& p) { return p.first == name; }),
          f.end());
  return f;
}

std::string to_json(const fields& f)
{
  std::string json = "{";
  for (const auto& [n, v] : f) {
    if (json.size() > 1) {
      json += ',';
    }
    json += '"' + n + "\":\"" + v + '"';
  }
  return json + '}';
}

bool verify(const std::string& token, const std::string& jwk_json)
{
  JSONParser parser;
  if (!parser.parse(jwk_json.c_str(), static_cast<int>(jwk_json.size()))) {
    ADD_FAILURE() << "invalid test JWK: " << jwk_json;
    return false;
  }
  const auto decoded = jwt::decode(token);
  bool verified = false;
  EXPECT_NO_THROW(verified = validate_signature_using_ec_jwk(
                      &dpp, decoded, decoded.get_algorithm(), parser));
  return verified;
}

bool verify(const std::string& token, const fields& jwk)
{
  return verify(token, to_json(jwk));
}

std::vector<std::string> jwks_keys(const std::string& jwks)
{
  JSONParser parser;
  if (!parser.parse(jwks.c_str(), static_cast<int>(jwks.size()))) {
    ADD_FAILURE() << "invalid test JWKS";
    return {};
  }
  JSONObj* keys = parser.find_obj("keys");
  if (!keys || !keys->is_array()) {
    ADD_FAILURE() << "test JWKS has no keys array";
    return {};
  }
  return keys->get_array_elements();
}

// Mirrors the bare-key branch of WebTokenEngine::validate_signature(): try the
// keys in order, EC keys with validate_signature_using_ec_jwk() and RSA keys
// with n and e, and stop at the first one that verifies the token.
std::optional<size_t> first_verifying_key(const std::string& token,
                                          const std::vector<std::string>& keys)
{
  const auto decoded = jwt::decode(token);
  const std::string& algorithm = decoded.get_algorithm();
  for (size_t i = 0; i < keys.size(); ++i) {
    JSONParser k_parser;
    if (!k_parser.parse(keys[i].c_str(), static_cast<int>(keys[i].size()))) {
      continue;
    }
    std::string kty;
    const bool has_kty = JSONDecoder::decode_json("kty", kty, &k_parser);
    if (has_kty && kty == "EC") {
      if (validate_signature_using_ec_jwk(&dpp, decoded, algorithm, k_parser)) {
        return i;
      }
      continue;
    }
    if (has_kty && kty != "RSA") {
      continue;
    }
    std::string n, e;
    if (algorithm == "RS256" && JSONDecoder::decode_json("n", n, &k_parser) &&
        JSONDecoder::decode_json("e", e, &k_parser)) {
      try {
        jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256().setModulusAndExponent(n, e))
            .verify(decoded);
        return i;
      } catch (const std::exception&) {
      }
    }
  }
  return std::nullopt;
}

} // anonymous namespace

TEST(STSEcJwk, CurveAlgorithm)
{
  EXPECT_EQ("ES256", ec_jwk_curve_algorithm("P-256"));
  EXPECT_EQ("ES384", ec_jwk_curve_algorithm("P-384"));
  EXPECT_EQ("ES512", ec_jwk_curve_algorithm("P-521"));
  EXPECT_TRUE(ec_jwk_curve_algorithm("secp256k1").empty());
  EXPECT_TRUE(ec_jwk_curve_algorithm("p-256").empty());
}

class STSEcJwkCurve : public ::testing::TestWithParam<const char*> {};

TEST_P(STSEcJwkCurve, VerifiesTokenSignedWithKey)
{
  const auto key = make_ec_key(GetParam());
  const auto token = sign(key);
  EXPECT_TRUE(verify(token, ec_jwk(key)));
  // "alg" is optional in a JWK, and "use" is checked by the caller
  EXPECT_TRUE(verify(token, without(ec_jwk(key), "alg")));
  EXPECT_TRUE(verify(token, with(ec_jwk(key), "use", "sig")));
}

TEST_P(STSEcJwkCurve, RejectsTamperedPayload)
{
  const auto key = make_ec_key(GetParam());
  const auto token = sign(key);
  auto payload = jwt::decode(token).get_payload();
  const auto pos = payload.find("example.org");
  ASSERT_NE(std::string::npos, pos);
  payload.replace(pos, 11, "example.net");
  EXPECT_FALSE(verify(with_payload(token, payload), ec_jwk(key)));
}

TEST_P(STSEcJwkCurve, RejectsTamperedSignature)
{
  const auto key = make_ec_key(GetParam());
  const auto token = sign(key);
  const auto sig = jwt::decode(token).get_signature();
  // flip a bit in R, then in S
  for (const size_t i : {sig.size() / 4, sig.size() * 3 / 4}) {
    SCOPED_TRACE(i);
    auto tampered = sig;
    tampered[i] ^= 0x01;
    EXPECT_FALSE(verify(with_signature(token, tampered), ec_jwk(key)));
  }
}

TEST_P(STSEcJwkCurve, RejectsSignatureOfWrongLength)
{
  const auto key = make_ec_key(GetParam());
  const auto token = sign(key);
  const auto sig = jwt::decode(token).get_signature();
  EXPECT_FALSE(verify(with_signature(token, sig.substr(0, sig.size() - 1)), ec_jwk(key)));
  EXPECT_FALSE(verify(with_signature(token, sig + '\0'), ec_jwk(key)));
  // 0x00 || R || 0x00 || S still splits into the right R and S, so only the
  // length check rejects it
  const auto half = sig.size() / 2;
  const auto padded = std::string(1, '\0') + sig.substr(0, half) + '\0' + sig.substr(half);
  EXPECT_FALSE(verify(with_signature(token, padded), ec_jwk(key)));
}

TEST_P(STSEcJwkCurve, RejectsCoordinatesOfWrongLength)
{
  const auto key = make_ec_key(GetParam());
  const auto token = sign(key);
  const auto x = decode_base64url_unpadded(key.x);
  const auto y = decode_base64url_unpadded(key.y);
  EXPECT_FALSE(verify(token, with(ec_jwk(key), "x", b64url(x.substr(1)))));
  EXPECT_FALSE(verify(token, with(ec_jwk(key), "x", b64url(std::string(1, '\0') + x))));
  EXPECT_FALSE(verify(token, with(ec_jwk(key), "y", b64url(y.substr(1)))));
}

TEST_P(STSEcJwkCurve, RejectsPointNotOnCurve)
{
  const auto key = make_ec_key(GetParam());
  auto y = decode_base64url_unpadded(key.y);
  y.back() ^= 0x01;
  EXPECT_FALSE(verify(sign(key), with(ec_jwk(key), "y", b64url(y))));
}

INSTANTIATE_TEST_SUITE_P(Curves, STSEcJwkCurve, ::testing::Values("P-256", "P-384", "P-521"));

TEST(STSEcJwk, RejectsMissingParameters)
{
  const auto key = make_ec_key("P-256");
  const auto token = sign(key);
  EXPECT_FALSE(verify(token, without(ec_jwk(key), "x")));
  EXPECT_FALSE(verify(token, without(ec_jwk(key), "y")));
  EXPECT_FALSE(verify(token, without(ec_jwk(key), "crv")));
  EXPECT_FALSE(verify(token, without(ec_jwk(key), "kty")));
}

TEST(STSEcJwk, RejectsExpiredToken)
{
  const auto key = make_ec_key("P-384");
  EXPECT_FALSE(verify(sign(key, -1h), ec_jwk(key)));
}

TEST(STSEcJwk, RejectsTokenAlgorithmThatDoesNotMatchCurve)
{
  const auto p256 = make_ec_key("P-256");
  const auto p384 = make_ec_key("P-384");
  // ES384 token against a P-256 key, and the reverse
  EXPECT_FALSE(verify(sign(p384), ec_jwk(p256)));
  EXPECT_FALSE(verify(sign(p256), ec_jwk(p384)));
  // the right key, but labelled with another curve
  EXPECT_FALSE(verify(sign(p384), with(ec_jwk(p384), "crv", "P-256")));
  // RS256 token against an EC key
  EXPECT_FALSE(verify(sign(shared_rsa_key()), without(ec_jwk(p256), "alg")));
}

TEST(STSEcJwk, RejectsJwkAlgThatDoesNotMatchToken)
{
  const auto key = make_ec_key("P-384");
  EXPECT_FALSE(verify(sign(key), with(ec_jwk(key), "alg", "ES256")));
}

TEST(STSEcJwk, RejectsUnsupportedCurves)
{
  const auto key = make_ec_key("P-256");
  const auto token = sign(key);
  for (const char* crv : {"secp256k1", "P-224", ""}) {
    SCOPED_TRACE(crv);
    EXPECT_FALSE(verify(token, with(ec_jwk(key), "crv", crv)));
  }
}

TEST(STSEcJwk, RejectsKeysThatAreNotEc)
{
  const auto token = sign(make_ec_key("P-256"));
  EXPECT_FALSE(verify(token, R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})"));
  EXPECT_FALSE(verify(token, R"({"kty":"oct","k":"c2VjcmV0"})"));
}

TEST(STSEcJwk, RejectsMalformedCoordinates)
{
  const auto key = make_ec_key("P-256");
  const auto token = sign(key);
  EXPECT_FALSE(verify(token, with(ec_jwk(key), "x", "!!!not base64!!!")));
  EXPECT_FALSE(verify(token, with(ec_jwk(key), "y", "=")));
}

TEST(STSEcJwk, SpireJwksFixture)
{
  const auto keys = jwks_keys(spire_jwks);
  ASSERT_EQ(3u, keys.size());
  EXPECT_FALSE(verify(spire_token, keys[0]));
  EXPECT_TRUE(verify(spire_token, keys[1]));
  EXPECT_FALSE(verify(spire_token, keys[2]));
  EXPECT_EQ(std::optional<size_t>{1}, first_verifying_key(spire_token, keys));
}

TEST(STSEcJwk, MixedJwks)
{
  const auto& rsa = shared_rsa_key();
  const auto p384 = make_ec_key("P-384");
  auto off_curve = decode_base64url_unpadded(p384.y);
  off_curve.back() ^= 0x01;
  // bad keys first, which must not stop the keys after them
  const std::vector<std::string> bad{
    R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})",
    to_json(with(ec_jwk(p384), "crv", "secp256k1")),
    to_json(without(ec_jwk(p384), "y")),
    to_json(with(ec_jwk(p384), "y", b64url(off_curve)))};

  auto ec_then_rsa = bad;
  ec_then_rsa.push_back(to_json(ec_jwk(p384)));
  ec_then_rsa.push_back(to_json(rsa_jwk(rsa)));
  EXPECT_EQ(std::optional<size_t>{bad.size()}, first_verifying_key(sign(p384), ec_then_rsa));
  EXPECT_EQ(std::optional<size_t>{bad.size() + 1}, first_verifying_key(sign(rsa), ec_then_rsa));

  auto rsa_then_ec = bad;
  rsa_then_ec.push_back(to_json(rsa_jwk(rsa)));
  rsa_then_ec.push_back(to_json(ec_jwk(p384)));
  EXPECT_EQ(std::optional<size_t>{bad.size()}, first_verifying_key(sign(rsa), rsa_then_ec));
  EXPECT_EQ(std::optional<size_t>{bad.size() + 1}, first_verifying_key(sign(p384), rsa_then_ec));
}

TEST(STSEcJwk, KeylessAlgorithmCannotSignOrVerify)
{
  EXPECT_THROW(jwt::algorithm::es384().verify("data", std::string(96, '\1')), jwt::signature_verification_exception);
  EXPECT_THROW(jwt::algorithm::es384().sign("data"), jwt::signature_generation_exception);
}
