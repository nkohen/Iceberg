THIS IS A WORK-IN-PROGRESS REFERENCE IMPLMENTATION THAT SHOULD NOT BE USED IN PRODUCTION.

Iceberg is a Verifiable Pseudorandom Secret Sharing (VPSS) based threshold-MuSig partial signing scheme loosely based on [Arctic](https://eprint.iacr.org/2024/466).

This enables a [MuSig](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) participant to use a t-of-n threshold key sharing instead of a single key.

Iceberg is designed to be optimal for use with the [Lightning Network](https://github.com/lightning/bolts) as it does not incur extra rounds of communication, allows different quorums of participants to be online during each signing round, and uses deterministic nonces (making it stateless).

Note that Iceberg requires an honest majority (quorum size >= 2t - 1), and is only performant when nCt is small.
