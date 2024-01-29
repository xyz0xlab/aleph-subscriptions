Aleph zero subscriptions with zero knowledge proofs
===================================================

This project builds an extension of the subscriptions smart contract that allows for registration and cancellation of recurring subscriptions (payments), 
which are based on validity of zero knowledge proof, e.g.

* subscriptions for adults only (18+)

The zero knowledge proof (ZKP) for minimum age was written using the `halo2` library. It proves that the user (submitter) is older than the required minimum age. 
In production, verified credentials or trusted identity provider may be clients of this service.
The `Subscriptions` smart contract allows to register a new subscription, cancel a subscription, and payment settlement for payment intervals. 
Each new subscription requires positive verification of the ZKP proof.

# Structure

This repository contains the following sub projects:

1. [ZKP proof for minimum required age](./proofs)
2. [Command line tool to interact with aleph zero chain](./subscriptions-client)
3. [Subscription smart contract with zero knowledge proof](./contracts/subscriptions)


