# kaspa-cli

`kaspa-cli` is the interactive command-line wallet and node-control shell for
Rusty Kaspa. It manages local HD wallets (single-signature and multisig),
connects to a `kaspad` node over wRPC, and signs and broadcasts transactions.
This guide covers wallet operation end to end, with an emphasis on the multisig
workflow (Schnorr and ECDSA, K-of-N signing, the cosigner ceremony, and PSKB
partial-signing).

The shell has a built-in quick reference: type `guide` at the prompt, or `help`
for the command list.

## 1. Overview and prerequisites

A wallet needs a `kaspad` node with the UTXO index enabled and the Borsh wRPC
interface listening:

```
kaspad --testnet --utxoindex --rpclisten-borsh=0.0.0.0
```

Drop `--testnet` for mainnet. `--utxoindex` is required so the wallet can scan
account UTXOs; `--rpclisten-borsh` exposes the interface `kaspa-cli` connects to.

Start the shell and point it at a network and a node:

```
network testnet-10          # set the active network (mainnet, testnet-10, testnet-11)
server 127.0.0.1            # set the RPC server (host of your kaspad), or `server public`
connect                     # connect to the configured server
```

`network` and `server` are stored in the application settings and reused on the
next run. `connect public` connects to the public node infrastructure instead of
a configured server.

## 2. Single-signature wallet

Create a wallet, then transact from its default account:

```
wallet create [<name>]      # create a wallet (default name "kaspa"); record the mnemonic
open <name>                 # open a wallet (a freshly created wallet is opened automatically)
list                        # list accounts and their balances
select <account>            # select the active account (name prefix or id)
address                     # show the active account's receive address
send <address> <amount>     # send funds to an address
sweep                       # consolidate the account's UTXOs
transfer <account> <amount> # move funds to another account in the same wallet
estimate <amount>           # fee and UTXO-consumption estimate
history list                # past transactions
```

`wallet create` prompts for the mnemonic word count (press Enter for 12, or type
24) and the signing curve (press Enter for Schnorr, or type `ecdsa`). Create more
single-signature accounts with `account create bip32 [<name>]`, or add an
account from a separate mnemonic with `account import mnemonic bip32`
(section 3).

`wallet import [mnemonic] [<name>]` restores a wallet from an existing mnemonic
and auto-discovers its single-signature bip32 accounts by walking the BIP-44
account index with the standard gap limit, registering every account that
carries a non-zero balance. Multisig accounts are never auto-discovered - a
multisig participation needs the peer xpubs, which are not in the seed;
re-register them explicitly (section 4).

## 3. The wallet is a multi-key container

A wallet file holds any number of separately-encrypted private keys, and every
account references the key it derives from. BIP-44 governs derivation paths,
not key retention: importing a second mnemonic adds a second key entry next to
the first. Re-importing a key the wallet already holds reuses the existing
entry rather than storing a duplicate, so one key can back several accounts
and several multisig groups.

The account operator surface, by key flow:

| Operation | Command |
|---|---|
| Create the container | `wallet create [<name>]` (fresh seed + default bip32 account), or `wallet create --container [<name>]` (empty container) |
| Restore the container | `wallet import [mnemonic] [<name>]` (bip32 discovery; section 2) |
| Restore container + multisig in one pass | `wallet import multisig [<name>]` or `wallet import mnemonic multisig [<name>]` |
| Import a Go keyfile into a new container | `wallet import go-data [<path>] [<name>]` |
| Add a single-sig account from a separate mnemonic | `account import mnemonic bip32` (24-word) or `account import mnemonic legacy` (12-word KDX) |
| Join a multisig group with your mnemonic | `account import mnemonic multisig` (prompts for the full cosigner xpub set + K) |
| Import a Go keyfile into an open wallet | `account import go-data [<path>]` |
| Create a multisig group from a wallet key | `account create multisig [<name>]` |
| Watch-only | `account watch bip32` / `account watch multisig` (xpubs only, no signing) |
| Import legacy KDX data | `account import legacy-data` |

Where a public key (xpub) is used:

- **Produce your xpub** to hand to peers: the `account create multisig` wizard
  prints it; `account details` lists the account's cosigner xpub set; `export`
  prints extended public keys.
- **Consume xpubs**: `account create multisig` consumes peer xpubs;
  `wallet import multisig`, `wallet import mnemonic multisig`, and
  `account import mnemonic multisig` consume the full cosigner xpub set
  including your own; `account watch multisig` and `account watch bip32`
  consume xpubs only.
- **Derive the shared address**: the receive address is determined by the full
  sorted cosigner-xpub set (section 5).
- **Sign with a public key**: `message sign` / `message verify` operate on
  Schnorr P2PK addresses; `pskb script lock` / `pskb script unlock` consume a
  `{{pubkey}}` placeholder in P2SH payloads.
- **Spend**: `send` / `sweep` / `transfer` on accounts whose local keys meet
  the threshold; the PSKB round-trip for split K-of-N groups (section 6).

## 4. Multisig accounts

A multisig account spends from a single shared P2SH address whose redeem script
requires K of N cosigner signatures. Create one with:

```
account create multisig [<name>]
```

The wizard prompts, in order, for:

- the wallet password (and payment password if the wallet uses one);
- the **minimum number of signatures** required (K);
- the **seat index** (press Enter to auto-assign the lowest unused seat on the
  selected wallet key);
- the **signing curve** (press Enter for Schnorr, or type `ecdsa`);
- the **number of additional cosigner extended public keys** (the peers' xpubs);
- each peer xpub in turn.

The account derives from the wallet key you select. The picker also offers
`N` to create and back up a new mnemonic private key before continuing. To join
a group with a cosigner mnemonic the wallet does not hold yet, use
`account import mnemonic multisig`, which imports the key and registers the
group in one pass. That import asks for the full cosigner xpub set, including
the xpub that belongs to the imported mnemonic, so the wallet can identify the
correct seat before storing the key. The seat index selects your own signing
branch within the shared group, while the wallet-local account slot is separate
bookkeeping. The receive address itself is determined by the full sorted
cosigner-xpub set, so every cosigner sees the same address.

The cosigner count is capped so the redeem script stays within consensus
standardness limits: up to 15 cosigners for Schnorr. The ECDSA limit is one
lower, because ECDSA public keys are one byte larger and fewer fit within the
same script-element limit. The wizard rejects a cosigner set that exceeds the
applicable limit, and rejects a threshold larger than the cosigner count.

Watch-only variant (all-external cosigners, no local signing key):

```
account watch multisig
```

To re-establish a multisig participation from an existing mnemonic, either
import it into the open wallet with `account import mnemonic multisig`, or
restore a fresh wallet and register the group in one pass with
`wallet import multisig` or `wallet import mnemonic multisig` (for Go-wallet address parity see section 8).
For a legacy Go keyfile, use `account import go-data [<path>]` in an open wallet
or `wallet import go-data [<path>] [<name>]` to create an empty container and
import the keyfile directly.

## 5. Cosigner ceremony

Each operator runs the same `account create multisig` flow on their own wallet
and exchanges extended public keys out of band:

1. After you enter K, the seat index, and the curve, the wizard prints **your**
   extended public key for that seat and curve, for example:

   ```
   extended public key (seat=0, curve=schnorr):

   <your-xpub>
   ```

   Copy it to your shared channel.

2. Collect every peer's xpub the same way. When the wizard asks for the number of
   additional cosigner xpubs, enter the count, then paste each peer xpub.

3. The wizard echoes the **constructed cosigner xpub set in canonical sort order**:

   ```
   cosigner xpub set (2-of-3):

   <xpub-a>
   <xpub-b>
   <xpub-c>
   ```

   Because the set is sorted deterministically, every operator who registers the same
   xpub set produces a byte-identical set - and therefore the same shared P2SH receive
   address. Each cosigner picks their own local seat index to derive their own xpub;
   cosigners do **not** share a seat - the address matches because the exchanged xpub
   set matches. (Seat index 0 matters only when matching an existing Go wallet -
   see section 8.) Compare the receive address (`address`) across operators to confirm
   the ceremony matched before funding it.

All cosigner xpubs must belong to the same network as the wallet (a testnet
wallet rejects a mainnet xpub and vice versa).

## 6. Spending from a multisig account

How a spend completes depends on how many cosigner keys the signing wallet holds:

- **1-of-1** multisig routes through the single-signature (P2PK) path; `send`,
  `sweep`, and `transfer` work directly.
- **K-of-N where one wallet holds all K required keys** also completes directly
  with `send`, `sweep`, or `transfer` - the wallet assembles the full signature
  set and broadcasts.
- **K-of-N split across separate wallets** (each holding one seat) uses the PSKB
  partial-signing round-trip. A direct `send` from a wallet that holds fewer than K
  local keys returns `MultisigInsufficientCosignerMaterial`; use PSKB instead.

PSKB round-trip:

```
pskb create <address> <amount> [<priority fee>]   # one cosigner builds the bundle; prints the encoded PSKB
pskb sign <pskb>                                   # each cosigner signs in turn; prints the updated PSKB
pskb send <pskb>                                   # once K signatures are present, broadcast; prints the tx ids
pskb parse <pskb>                                  # inspect a bundle at any stage
```

Circulate the PSKB string from one cosigner to the next, each running `pskb sign`,
until it carries the threshold number of signatures, then `pskb send` broadcasts
it. The finalizer accepts exactly the threshold number of signatures and rejects a
bundle that carries more.

## 7. ECDSA multisig

Select ECDSA at the curve prompt (`ecdsa`) when creating the account. ECDSA
multisig produces an `OP_CHECKMULTISIGECDSA` redeem script over 33-byte compressed
public keys (Schnorr uses 32-byte x-only keys). Signatures are RFC-6979
deterministic.

Choose ECDSA for cross-binary compatibility with the canonical Go `kaspawallet`,
which derives ECDSA multisig addresses; a Schnorr account and an ECDSA account over
the same cosigner set produce different addresses, so all cosigners must agree on
the curve up front. The ECDSA cosigner cap is one lower than Schnorr's (larger
public keys); the wizard enforces it.

## 8. Re-creating a Go multisig wallet (address parity)

An operator with an existing Go `kaspawallet` multisig can re-create the same
wallet in `kaspa-cli` and reach byte-identical addresses, then co-sign with other
`kaspa-cli` cosigners over PSKB. The direct keyfile route is:

```
wallet import go-data [<path>] [<name>]   # new empty container + imported Go keyfile
account import go-data [<path>]           # import into the currently open wallet
```

Both commands auto-detect single-key vs multisig and Go keyfile version. Go
multisig keyfiles always prove their seat at index 0 (the Go derivation path is
fixed); the wallet-local account slot is auto-assigned, so an occupied slot 0
never blocks the import. Re-registering a cosigner set the wallet already holds
rejects through the duplicate-group guard instead. The mnemonic route below
remains useful when you want to
manually re-register the cosigner set. It uses the Go wallet's mnemonic and the
cosigner xpubs only - no partial-transaction/protobuf interop and no on-disk
format conversion. Restore the mnemonic at the **wallet** level as below, or
import it into an already-open wallet with `account import mnemonic multisig`.

1. Restore the wallet from the Go wallet's mnemonic (the wizard prompts for the
   mnemonic):

   ```
   wallet import [<name>]
   ```

2. Create the multisig account from that master and the peer xpubs, choosing seat
   index 0 - the Go wallet derives multisig at `m/45'/111111'/0'`:

   ```
   account create multisig
   ```

3. Confirm the receive address (`address`) is byte-identical to the address the Go
   wallet shows for the same cosigner set at seat index 0. Matching addresses
   confirm the derivation and the sorted cosigner-xpub set agree.

4. Spend with the PSKB round-trip in section 6: each cosigner runs `pskb sign`, and
   `pskb send` broadcasts once the threshold is met.

## 9. Derivation reference

- **Coin type:** `111111'` (Kaspa), on every account kind.
- **Single-signature (BIP-32 / BIP-44):** purpose `44'`,
  `m/44'/111111'/<account>'/<change>/<index>`.
- **Multisig (BIP-87-inspired, over the Kaspa/go-wallet purpose-`45'` path):**
  `m/45'/111111'/<seat>'/<cosigner_index>/<address_type>/<address_index>`. This
  follows the BIP-44 account model with cosigner-xpub registration; it is **not** full
  BIP-87 (which uses purpose `87'`, drops the cosigner-index level, and restores from
  descriptors).
- **Go compatibility:** the Go `kaspawallet` hardcodes multisig at
  `m/45'/111111'/0'`; `kaspa-cli` is address-compatible at seat index 0.
  `wallet/account import go-data` imports that fixed seat and auto-assigns
  the wallet-local account slot.
- The multisig **seat index** is hardened and selects an operator's own signing
  branch within a cosigner group; it does not change the shared receive address,
  which is the P2SH of the full sorted cosigner-xpub set. The **account slot**
  is the wallet-local selector and never enters derivation.
- `account details` prints the account slot and the seat of every cosigner
  xpub. `export mnemonic` prints the slot and the seat indexes and derives the
  exported xpub at its seat.
- A wallet holds **any number of separately-encrypted keys**; every account -
  single-sig and multisig - references the key it derives from.

## 10. Troubleshooting

- **"too many cosigners" / cap rejection at create.** The cosigner set exceeds the
  standardness limit (15 for Schnorr, one lower for ECDSA). Reduce the cosigner
  count, or split into separate accounts.
- **xpub rejected for the wrong network.** Cosigner xpubs must match the wallet's
  network (mainnet vs testnet prefixes). Re-export the xpub from a wallet on the
  correct network.
- **`MultisigInsufficientCosignerMaterial` on `send`/`sweep`.** The signing wallet
  holds fewer than K cosigner keys. Use the PSKB round-trip (section 6) so each
  cosigner signs separately.
- **Addresses do not match across cosigners (or against the Go wallet).** The
  mnemonics, the peer xpub set, the seat index, or the curve differ between
  operators. All four must match for the sorted cosigner-xpub set - and therefore
  the address - to be identical.
- **Opening another wallet after a multisig import.** This is clean: the import
  commits its storage so the wallet does not report unsaved changes on the next
  `open`.
