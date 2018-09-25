#define CATCH_CONFIG_MAIN

#include "catch2.hpp"
#include "../src/lamportkeys.h"

#include <sodium.h>
#include <cstring>


TEST_CASE("Private keys hashes are computed", "[key hash]" ) {
    using namespace crypto::lamport;

    sodium_init();

    PrivateKey pKey;

    SECTION("Generated hash must be equal to reference hash") {
        BLAKE2KeyHash h(pKey);

        byte referenceHash[BLAKE2KeyHash::kBytesSize];
        auto guard = pKey.data()->unlockAndInitGuard();
        crypto_generichash(
            referenceHash,
            BLAKE2KeyHash::kBytesSize,
            guard.address(),
            PrivateKey::kKeySize(),
            nullptr,
            0);

        REQUIRE(memcmp(h.data(), referenceHash, 32) == 0);
    }

    SECTION("Generated via shared pointer hash must be equal to reference hash") {
        auto s = make_shared<PrivateKey>();
        BLAKE2KeyHash h(s);

        byte referenceHash[BLAKE2KeyHash::kBytesSize];
        auto guard = s->data()->unlockAndInitGuard();
        crypto_generichash(
            referenceHash,
            BLAKE2KeyHash::kBytesSize,
            guard.address(),
            PrivateKey::kKeySize(),
            nullptr,
            0);

        REQUIRE(memcmp(h.data(), referenceHash, 32) == 0);
    }

    SECTION("Two hashes from common key must be equal") {
        BLAKE2KeyHash h1(pKey);
        BLAKE2KeyHash h2(pKey);

        REQUIRE(h1 == h2);
    }

    SECTION("Two hashes from common key must be equal (!= operator check)") {
        BLAKE2KeyHash h1(pKey);
        BLAKE2KeyHash h2(pKey);

        REQUIRE(!(h1 != h2));
    }
}

TEST_CASE("Public keys hashes are computed", "[key hash]" ) {
    using namespace crypto::lamport;

    sodium_init();

    PrivateKey pKey;
    auto pubKey = pKey.derivePublicKey();

    SECTION("Generated hash must equal to reference hash") {
        BLAKE2KeyHash h(pubKey);

        byte referenceHash[BLAKE2KeyHash::kBytesSize];
        crypto_generichash(
            referenceHash,
            BLAKE2KeyHash::kBytesSize,
            pubKey->data(),
            PublicKey::kKeySize(),
            nullptr,
            0);

        REQUIRE(memcmp(h.data(), referenceHash, 32) == 0);
    }

    SECTION("Two hashes from common key must be equal") {
        BLAKE2KeyHash h1(pubKey);
        BLAKE2KeyHash h2(pubKey);

        REQUIRE(h1 == h2);
    }

    SECTION("Two hashes from common key must be equal (!= operator check)") {
        BLAKE2KeyHash h1(pubKey);
        BLAKE2KeyHash h2(pubKey);

        REQUIRE(!(h1 != h2));
    }
}