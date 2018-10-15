#ifndef LAMPORTSCHEME_H
#define LAMPORTSCHEME_H

#include "lamportkeys.h"

#include <bitset>
#include <cstring>


namespace crypto {
namespace lamport {

using namespace std;

/**
 * Todo: add description
 *
 * Tests: Signature
 */
class Signature {
public:
    typedef shared_ptr<Signature> Shared;

public:
    explicit Signature(
        byte *data,
        size_t dataSize,
        PrivateKey *pKey);

    explicit Signature(
        byte *data);

    ~Signature();

    static const size_t signatureSize();

public:
    bool check(
        byte *data,
        size_t dataSize,
        PublicKey::Shared pubKey)
        noexcept;

    const byte* data() const;

protected:
    void collectSignature(
        byte *key,
        byte *sign,
        byte *messageHash)
        noexcept;

public:
    static const size_t kSize =
        PrivateKey::kRandomNumberSize * PrivateKey::kRandomNumbersCount / 2;

protected:
    unsigned char *mData;
};


}
}

#endif // LAMPORTSCHEME_H
