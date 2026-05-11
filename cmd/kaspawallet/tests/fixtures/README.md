# Legacy Go-keyfile fixtures

Every keyfile here was emitted by the Go `cmd/kaspawallet` binary
(`kaspanet/kaspad` master at v0.12.22, binary at
`/home/dima/work/kaspa/kaspad/bin/kaspawallet`). The passphrases
are test secrets, not real wallet keys — none of these keyfiles
hold funds.

| Fixture | Generator command | Passphrase | Mnemonic(s) |
|---|---|---|---|
| `legacy_go_v1_singlekey.json` | `kaspawallet --testnet create --num-private-keys=1 --num-public-keys=1 --min-signatures=1 --yes` | `test fixture passphrase` | `ethics brand merge engine core arm mail image punch mail absent private pioneer present enforce sorry another lazy hero alpha little glide fossil virus` |
| `legacy_go_v1_ecdsa_singlekey.json` | `kaspawallet --testnet create --ecdsa --num-private-keys=1 --num-public-keys=1 --min-signatures=1 --yes` | `ecdsa test passphrase` | `evoke monkey potato feature lobster already casual become kitten kingdom cake someone awkward picture bird limb salon flee title satoshi educate depart casino cake` |
| `legacy_go_v1_multisig_2of3.json` | `kaspawallet --testnet create --num-private-keys=3 --num-public-keys=3 --min-signatures=2 --yes` | `multisig test passphrase` | `regular brief palm floor wish win ugly sentence powder skill clump crawl prosper increase garden put else payment coach voyage enforce cigar cream capital` &#124; `credit junior large vacant journey purpose leader pink stage success sting crack nothing immune island firm ankle problem harsh cloth onion armor snake blood` &#124; `scout silly solar abuse useless pigeon foot fitness job joke chunk spirit interest require battle deer casual ensure run album vapor leg spawn frame` |

`legacy_go_v0_singlekey.json` is intentionally not provided in this
seed: it would require an older Go reference (legacy v0 era), and
the v0 brute-force resolver is exercised in unit tests using a
synthetic fixture constructed in-test from a v1 keyfile re-keyed
under a chosen `numThreads`. See
`cmd/kaspawallet::keyfile::tests::test_v0_singlekey_numthreads_bruteforce`.

## Cross-wallet serialization fixture

`go_emitted_pst.hex` is a hex-encoded
`PartiallySignedTransaction` produced by the Go reference's
`libkaspawallet/serialization.SerializePartiallySignedTransaction`
on a deterministic synthetic input (single input, two outputs,
one cosigner xpub, no signatures attached). The fixture is the
ground truth for the cross-wallet wire-format AC (lead direction
2026-05-11, steer addendum 1778485777798-0).

`fixturegen.go.txt` is the Go helper that produced the fixture.
Reproduce with:

```bash
cd /home/dima/work/kaspa/kaspad
/home/dima/sdk/go1.23.4/bin/go run \
  cmd/kaspawallet/tests/fixtures/fixturegen.go.txt \
  > cmd/kaspawallet/tests/fixtures/go_emitted_pst.hex
```

(System PATH `go` is 1.22.2 and rejects kaspad's `go.mod` 1.23
requirement; the SDK at `/home/dima/sdk/go1.23.4/bin/go` is the
correct toolchain.)
