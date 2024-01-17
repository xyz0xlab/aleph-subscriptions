Aleph zero subscriptions with zero knowledge proofs
===================================================

This project builds an extension of the subscriptions smart contract that allows for registration and cancellation of recurring subscriptions (payments), 
which are based on validity of zero knowledge proof, e.g.

* subscription for adults only (18+)

# Structure

This repository contains the following sub projects:

1. [ZKP proof for minimum required age](./proofs)
2. [Command line tool to interact with aleph zero chain](./subscriptions-client)
