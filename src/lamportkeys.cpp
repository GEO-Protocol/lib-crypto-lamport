#include "lamportkeys.h"


namespace crypto {
namespace lamport {

const size_t AbstractKey::kKeySize()
{
    return kRandomNumbersCount * 32;
}

/*
 * ---------------------------------------------------------------------------------------------------------------------
 */

PrivateKey::PrivateKey():
    mData(memory::SecureSegment(kRandomNumbersCount * kRandomNumberSize)),
    mIsCropped(false)
{
    auto guard = mData.unlockAndInitGuard();

    auto offset = static_cast<byte*>(guard.address());
    for (size_t i=0; i<kRandomNumbersCount; ++i) {
        randombytes_buf(offset, kRandomNumberSize);
        offset += kRandomNumberSize;
    }
}

PrivateKey::PrivateKey(
    byte *data) :
    mData(memory::SecureSegment(kKeySize())),
    mIsCropped(false)
{
    auto guard = mData.unlockAndInitGuard();
    auto offset = static_cast<byte*>(guard.address());
    memcpy(
        offset,
        data,
        kKeySize());
}

/*
 * ---------------------------------------------------------------------------------------------------------------------
 */

PublicKey::Shared PrivateKey::derivePublicKey() {

    auto guard = mData.unlockAndInitGuard();
    auto generatedKey = make_shared<PublicKey>();

    // Numbers buffers memory allocation.
    generatedKey->mData = static_cast<byte*>(malloc(kRandomNumbersCount * kRandomNumberSize));
    if (generatedKey->mData == nullptr) {
        return nullptr;
    }

    // Numbers buffers initialisation via hashing private key numbers.
    auto source = static_cast<byte*>(guard.address());
    auto destination = static_cast<byte*>(generatedKey->mData);

    for (size_t i=0; i<kRandomNumbersCount; ++i) {
        crypto_generichash(destination, kRandomNumberSize, source, kRandomNumberSize, nullptr, 0);
        source += kRandomNumberSize;
        destination += kRandomNumberSize;
    }

    return generatedKey;
}

const memory::SecureSegment* PrivateKey::data() const
{
    return &mData;
}

PublicKey::PublicKey(
    byte *data)
{
    mData = static_cast<byte*>(
        malloc(
            kKeySize()));

    memcpy(
        mData,
        data,
        kKeySize());
}

PublicKey::~PublicKey()
noexcept
{
    if (mData != nullptr) {
        free(mData);
        mData = nullptr;
    }
}

const byte* PublicKey::data() const
{
    return mData;
}

BLAKE2KeyHash::BLAKE2KeyHash(
    byte* buffer)
{
    memcpy(
        mData,
        buffer,
        kBytesSize);
}

const byte* BLAKE2KeyHash::data() const
{
    return mData;
}


BLAKE2KeyHash::BLAKE2KeyHash(
    PublicKey::Shared key)
{
    crypto_generichash(
        mData,
        BLAKE2KeyHash::kBytesSize,
        key->data(),
        key->kKeySize(),
        nullptr,
        0);
}

BLAKE2KeyHash::BLAKE2KeyHash(
    const PrivateKey &key)
{
    auto guard = key.data()->unlockAndInitGuard();
    crypto_generichash(
        mData,
        BLAKE2KeyHash::kBytesSize,
        guard.address(),
        key.kKeySize(),
        nullptr,
        0);
}

BLAKE2KeyHash::BLAKE2KeyHash(
    PrivateKey::Shared key)
{
    auto guard = key->data()->unlockAndInitGuard();
    crypto_generichash(
        mData,
        BLAKE2KeyHash::kBytesSize,
        guard.address(),
        key->kKeySize(),
        nullptr,
        0);
}

bool operator== (const BLAKE2KeyHash &kh1, const BLAKE2KeyHash &kh2)
{
    return memcmp(kh1.mData, kh2.mData, BLAKE2KeyHash::kBytesSize) == 0;
}

bool operator!= (const BLAKE2KeyHash &kh1, const BLAKE2KeyHash &kh2)
{
    return ! (kh1 == kh2);
}


}
}

