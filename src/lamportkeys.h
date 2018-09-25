#ifndef LAMPORTKEYS_H
#define LAMPORTKEYS_H

#include "memory.h"

#include <sodium.h>

#include <boost/noncopyable.hpp>
#include <memory>
#include <cstring>


namespace crypto {
namespace lamport {

using namespace std;

/*
 * Base class for private and public keys.
 *
 * Tests: [abstract key]
 */
class AbstractKey:

    // Keys must not be copyable to prevent occasional key leak into memory.
    boost::noncopyable {

    friend class Signature;

public:
    /**
     * @returns size if bytes of Lamport Key.
     * Both PrivateKey and PublicKey are 16K long.
     */
    static const size_t kKeySize();

protected:
    static const size_t kRandomNumbersCount = 256 * 2;
    static const size_t kRandomNumberSize = 256 / 8;
};

/**
 * todo: implement tests
 */
class PublicKey:
    public AbstractKey {
    friend class PrivateKey;
    friend class Signature;

public:
    typedef shared_ptr<PublicKey> Shared;

public:
    using AbstractKey::AbstractKey;

    /**
     * Creates public key and initialises it with bytes from `data`.
     * @param data must be at least 16Kb long.
     */
    explicit PublicKey(
        byte* data);

    ~PublicKey()
        noexcept;

    /**
     * @returns bytes of the key.
     */
    const byte* data() const;

private:
    byte *mData;
};

/**
 * todo: implement tests
 */
class PrivateKey:
    public AbstractKey {
    friend class Signature;

public:
    typedef shared_ptr<PrivateKey> Shared;

public:
    /*
     * Creates private key and initialises it with cryptographic random data.
     */
    explicit PrivateKey();

    /**
     * Creates private key and initialises it with bytes from `data`.
     * @param data must be at least 16Kb long.
     */
    explicit PrivateKey(
        byte* data);

    /**
     * @returns public key, generated from current private key.
     */
    PublicKey::Shared derivePublicKey();

    /**
     * @returns secure segment with access to key's data.
     */
    const memory::SecureSegment* data() const;

private:
    memory::SecureSegment mData;
    bool mIsCropped;
};


/**
 * BLAKE2KeyHash implements container for storing, serialization and deserialization
 * of hashes of private and public keys.
 *
 * Implements hashing via BLAKE2 hash.
 * (https://download.libsodium.org/doc/hashing/generic_hashing)
 *
 * Tests: BLAKE2KeyHash
 */
class BLAKE2KeyHash {
public:
    typedef shared_ptr<BLAKE2KeyHash> Shared;

public:
    /**
     * Initialises the hash from the key itself.
     *
     * @param key - key which must be used for hash generation.
     */
    explicit BLAKE2KeyHash(
        const PrivateKey &key);

    /**
     * Initialises the hash from the key itself.
     *
     * @param key - key which must be used for hash generation.
     */
    explicit BLAKE2KeyHash(
        PrivateKey::Shared key);

    /**
     * Initialises the hash from the key itself.
     *
     * @param key - key which must be used for hash generation.
     */
    explicit BLAKE2KeyHash(
        PublicKey::Shared key);

    /**
     * Initialises the hash from the bytes stream.
     *
     * @param buffer - bytes source, that should be used as source of hash data.
     * Required length - at least 32 (kBytesSize).
     */
    explicit BLAKE2KeyHash(
        byte* buffer);

    /**
     * @returns hash as bytes stream;
     */
    const byte* data() const;

    friend bool operator== (
        const BLAKE2KeyHash &kh1,
        const BLAKE2KeyHash &kh2);

    friend bool operator!= (
        const BLAKE2KeyHash &kh1,
        const BLAKE2KeyHash &kh2);

public:
    static const size_t kBytesSize = 32;

private:
    // todo [Dima Chizhevsky, Mykola Ilashchuk]: Think about heap usage here.
    byte mData[kBytesSize];
};


}
}

#endif // LAMPORTKEYS_H
