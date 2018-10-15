
![logo](https://github.com/GEO-Protocol/lib-crypto-lamport/blob/master/resources/lamport_logo.png)



## Abstract
C++implementation of [Lamport One Time Signature](https://ru.wikipedia.org/wiki/%D0%9F%D0%BE%D0%B4%D0%BF%D0%B8%D1%81%D1%8C_%D0%9B%D1%8D%D0%BC%D0%BF%D0%BE%D1%80%D1%82%D0%B0) on top of [BLAKE2b](https://blake2.net).  
Used in [GEO Network client](https://github.com/GEO-Protocol/GEO-network-client) and [observers chain backend](https://github.com/GEO-Protocol/gns-observers-chain-back).

</br>

## How to use it

---
**WARN:** This is the soure-based library!  
It was not adapted/tested for binary library builds.

---

1. Clone this repo as a submodule into your project.  
  `git submodule add git@github.com:GEO-Protocol/lib-crypto-lamport.git crypto` </br></br>
1. Ensure `libsodium` is [initialised](https://download.libsodium.org/doc/usage) somewhere before the first call to this library. It doesn't check and initialize the `libsodium` itself for the performance purposes.

</br>

## Dependancies
* [libsoidum](https://download.libsodium.org/doc/);
* [catch2](https://github.com/catchorg/Catch2) (for the tests purposes).

</br>

## Tests
Basic operations tests are provided [here](https://github.com/GEO-Protocol/lib-crypto-lamport/tree/master/tests). 
