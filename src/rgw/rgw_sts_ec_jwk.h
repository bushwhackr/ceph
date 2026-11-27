// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <exception>
#include <string>
#include <string_view>

#include "common/ceph_json.h"
#include "common/dout.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "jwt-cpp/jwt.h"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop

namespace rgw::auth::sts::detail {

// The JWS algorithm that signs with each supported JWK curve
// (RFC 7518 sections 3.4 and 6.2.1.1), or "" for an unsupported curve.
inline std::string_view ec_jwk_curve_algorithm(std::string_view crv)
{
  if (crv == "P-256") {
    return "ES256";
  }
  if (crv == "P-384") {
    return "ES384";
  }
  if (crv == "P-521") {
    return "ES512";
  }
  return {};
}

// Verify the token's signature, and its expiry, with the public key given by
// the base64url "x" and "y" of an EC JWK on the curve that goes with algorithm.
// Returns false if the key is invalid or verification fails. Never throws.
inline bool validate_signature_using_ec_xy(const DoutPrefixProvider* dpp,
                                           const jwt::decoded_jwt& decoded,
                                           const std::string& algorithm,
                                           const std::string& x,
                                           const std::string& y)
{
  try {
    if (algorithm == "ES256") {
      jwt::verify()
          .allow_algorithm(jwt::algorithm::es256().setAffineCoordinates(x, y))
          .verify(decoded);
    } else if (algorithm == "ES384") {
      jwt::verify()
          .allow_algorithm(jwt::algorithm::es384().setAffineCoordinates(x, y))
          .verify(decoded);
    } else if (algorithm == "ES512") {
      jwt::verify()
          .allow_algorithm(jwt::algorithm::es512().setAffineCoordinates(x, y))
          .verify(decoded);
    } else {
      ldpp_dout(dpp, 10) << "Not an ECDSA algorithm: " << algorithm << dendl;
      return false;
    }
  } catch (const std::exception& e) {
    ldpp_dout(dpp, 10) << "Signature validation using EC x and y failed: "
                       << e.what() << dendl;
    return false;
  }
  ldpp_dout(dpp, 10) << "Verified signature using EC x and y" << dendl;
  return true;
}

// Verify the token with one bare EC JWK ("kty": "EC" with "crv", "x" and "y",
// no "x5c"). The key is only tried when its curve, and its "alg" if it has
// one, match the token's algorithm.
// Returns false, after logging why at level 10, if the key is malformed,
// unsupported or doesn't verify the token, so the caller can go on to the
// next key in the JWKS. Never throws.
inline bool validate_signature_using_ec_jwk(const DoutPrefixProvider* dpp,
                                            const jwt::decoded_jwt& decoded,
                                            const std::string& algorithm,
                                            JSONObj& jwk)
{
  try {
    std::string kty, crv, alg, x, y;
    if (!JSONDecoder::decode_json("kty", kty, &jwk) || kty != "EC") {
      ldpp_dout(dpp, 10) << "Not an EC key: kty=" << kty << dendl;
      return false;
    }
    if (!JSONDecoder::decode_json("crv", crv, &jwk)) {
      ldpp_dout(dpp, 10) << "EC key has no crv" << dendl;
      return false;
    }
    const std::string_view curve_algorithm = ec_jwk_curve_algorithm(crv);
    if (curve_algorithm.empty()) {
      ldpp_dout(dpp, 10) << "Unsupported EC key curve: crv=" << crv << dendl;
      return false;
    }
    if (algorithm != curve_algorithm) {
      ldpp_dout(dpp, 10) << "EC key on curve " << crv
                         << " can't verify a token signed with " << algorithm
                         << dendl;
      return false;
    }
    if (JSONDecoder::decode_json("alg", alg, &jwk) && alg != algorithm) {
      ldpp_dout(dpp, 10) << "EC key alg " << alg
                         << " doesn't match token alg " << algorithm << dendl;
      return false;
    }
    if (!JSONDecoder::decode_json("x", x, &jwk) ||
        !JSONDecoder::decode_json("y", y, &jwk)) {
      ldpp_dout(dpp, 10) << "EC key parameters (x&y) are not present for key"
                         << dendl;
      return false;
    }
    return validate_signature_using_ec_xy(dpp, decoded, algorithm, x, y);
  } catch (const std::exception& e) {
    ldpp_dout(dpp, 10) << "Failed to read EC key: " << e.what() << dendl;
    return false;
  }
}

} // namespace rgw::auth::sts::detail
