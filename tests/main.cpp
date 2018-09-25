#define CATCH_CONFIG_MAIN

#include "catch2.hpp"
#include "../src/lamportscheme.h"

#include <sodium.h>
#include <cstring>


using namespace crypto::lamport;

TEST_CASE("Abstract keys", "[AbstractKey]") {
    REQUIRE(PrivateKey::kKeySize() == 1024 * 16);
    REQUIRE(PublicKey::kKeySize() == 1024 * 16);

    class AbstractKeyTest: public AbstractKey {
    public:
        static const size_t kRandomNumbersCountTest(){
            return AbstractKeyTest::kRandomNumbersCount;
        }

        static const size_t kRandomNumberSizeTest(){
            return AbstractKeyTest::kRandomNumberSize;
        }
    };

    REQUIRE(AbstractKeyTest::kRandomNumbersCountTest() == 512);
    REQUIRE(AbstractKeyTest::kRandomNumberSizeTest() == 32);
}

TEST_CASE("Private keys hashes are computed", "[BLAKE2KeyHash]" ) {
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

TEST_CASE("Public keys hashes are computed", "[BLAKE2KeyHash]" ) {
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

TEST_CASE("Signatures generation", "[Signature]") {
    sodium_init();

    byte referenceData[] = "123456781234567812345678123456781234567812345678";

    PrivateKey pKey;
    auto pubKey = pKey.derivePublicKey();
    Signature sig(referenceData, sizeof referenceData, &pKey);

    SECTION("Signatures should pass check on reference data") {
        REQUIRE(sig.check(referenceData, sizeof referenceData, pubKey));
    }

    SECTION("Signatures should NOT pass check on some other data") {
        byte otherData[] = "1234";
        REQUIRE_FALSE(sig.check(otherData, sizeof otherData, pubKey));
    }
}