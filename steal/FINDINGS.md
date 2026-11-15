# Steal the VFY — Temuan Riset & Rancangan Implementasi

Ditulis 2026-11-15. Melengkapi `../STEAL-SPEC.md`: lima hal yang di sana
ditandai ⚠️ UNVERIFIED kini **terjawab**, sebagian besar lewat source circuit
asli yang berhasil di-recover seorang peserta dan terbukti meng-compile
menjadi WASM resmi byte-for-byte. Modul implementasi ada di folder ini
(`src/`), uji lokal di `test/run-tests.mjs` — **12/12 lolos**, termasuk
fullProve + `groth16.verify` terhadap VK resmi untuk turn EXTRACT, FORTIFY,
dan HOLD.

Sumber utama (disebut [SRC], [FVX], [JM], [OSO], [NES] di bawah):

- [SRC] https://github.com/smilewithkhushi/steal-the-vfy-reference — memuat
  `artifacts/source/vfy-policy.circom` (source circuit historis platform,
  git revision `63f05423…`, sha256 `d49e5f43…`) yang bila di-compile dengan
  Circom 2.2.3 + circomlib 2.0.5 menghasilkan WASM & R1CS resmi **byte-for-byte
  identik** (lihat `artifacts/source/provenance.json` di repo itu), plus
  `docs/PROTOCOL.md` dan `docs/GAME.md`.
- [FVX] https://github.com/fvxkrz/Steal-the-vfy — analisis circuit independen
  lewat probing witness (469 percobaan, 110 diterima, 11 proof asli
  terverifikasi): `docs/circuit-analysis.md`, `docs/PROTOCOL_GAPS.md`.
- [JM] https://github.com/JM-03/agent-games-steal-the-vfy — `CIRCUIT_NOTES.md`
  menyatakan semantik yang sama ditemukan dari **tiga repo peserta independen
  yang saling cocok**, lalu dibuktikan dengan fullProve + verify lokal.
- [OSO] https://github.com/oso161x/steal-agent — implementasi Node berjalan
  (`STRATEGY.md`, `server.mjs`).
- [NES] https://github.com/nestic-id/agentgames-agent —
  `src/witness-config.steal.json` (peta envelope → witness).
- Resmi: https://agentgames.zkverify.io/build (§06),
  https://agentgames.zkverify.io/events/steal-the-vfy,
  https://agentgames.zkverify.io/api/circuit-info

---

## 1. Nama field persis envelope request/response turn

**Request (platform → agent)**, skema gabungan [FVX `src/protocol.ts`],
[JM `src/types.ts`], [SRC `src/protocol.ts`], [NES witness-config] — keempatnya
sepakat:

```json
{
  "protocolVersion": "v1",
  "eventId": "steal-the-vfy",
  "mode": "practice" | "competition",
  "matchId": "<UUID>",
  "turn": 1,
  "issuedAt": "<ISO-8601>",
  "deadlineAt": "<ISO-8601>",
  "state": {
    "selfBalance": "100",
    "opponentBalance": "100",
    "selfFortifiedUntilTurn": null,
    "opponentFortifiedUntilTurn": null
  },
  "strategyCommitment": { "hash": "0x<64 hex>" },
  "resolverVersion": "v1",
  "nonce": "<string>"
}
```

Catatan: balance adalah **string desimal**; `selfFortifiedUntilTurn` /
`opponentFortifiedUntilTurn` ada di envelope tapi **bukan** input circuit.
Berbeda dengan Gatekeeper, envelope Steal **tidak** dibungkus `type` —
diskriminatornya `eventId: "steal-the-vfy"` (preflight tetap memakai
`type: "agent-games.preflight.v1"`).

**Response (agent → platform)**:

```json
{
  "protocolVersion": "v1",
  "matchId": "<echo persis>",
  "turn": 1,
  "action": { "type": "EXTRACT", "amount": 10 },
  "policyProof": {
    "circuitVersion": "v1",
    "proof": { },
    "publicSignals": ["...9 string..."],
    "publicInputsHash": "0x<64 hex>"
  },
  "agentTimestamp": "<ISO-8601>",
  "idempotencyKey": "<unik per turn>"
}
```

- `action` adalah discriminated union: `{type:"HOLD"}` / `{type:"FORTIFY"}`
  **tanpa** field `amount` sama sekali (schema menolaknya walau 0), dan
  `{type:"EXTRACT", amount}` hanya untuk EXTRACT [/build §06, semua repo].
- **Satu-satunya divergensi antar-implementasi:** penempatan proof.
  [JM] + [OSO] menaruh `proof` + `publicSignals` (camelCase) di dalam
  `policyProof`; [SRC] + [FVX] menaruh `proof` + `public_signals` (snake_case)
  di top level di samping `policyProof`. /build hanya berkata "attach your
  policy proof (circuitVersion plus the Groth16 proof and public_signals)".
  Modul ini default mengirim **keduanya** (`proofPlacement: 'both'` di
  `src/turn.mjs`) agar tidak kena risiko missing-field (= di-skor HOLD);
  lihat daftar konfirmasi §6 butir 1.
- `publicInputsHash` — resep resmi /build §06, identik di [FVX], [JM], [SRC],
  [OSO], [NES]: **Keccak256 atas 8 word uint256 big-endian 32-byte**, urutan:
  commitment, matchId (UUID tanpa strip → integer heksadesimal), turn,
  selfBalance, opponentBalance, kode aksi, amount (0 untuk non-EXTRACT),
  circuitVersion "v1" → 1. Bukan SHA3-256, bukan Poseidon, dan **tidak**
  memuat output circuit. Vektor uji [FVX] terverifikasi ulang di modul ini:
  word `[16038997112020182322173448379678790230845526951830566086947884141750627046316, 123456789, 3, 95, 105, 2, 10, 1]`
  → `0xb4f366c80484380d513b716bf241fb3bdd734547a2c76ad65abe88209b1b362d` ✓.

## 2. Encoding numerik aksi di circuit

**HOLD = 0, FORTIFY = 1, EXTRACT = 2** — tertulis eksplisit di komentar source
circuit [SRC `vfy-policy.circom` baris 14] dan dipakai konsisten oleh semua
repo serta resep publicInputsHash.

## 3. Cap EXTRACT dan biaya FORTIFY

Dari komentar "Resolver constants" di source circuit [SRC], dikonfirmasi
[SRC `docs/GAME.md`] dan [OSO `STRATEGY.md`]:

| Konstanta | Nilai | Ditegakkan di |
|---|---|---|
| `extractCap` | **10** — params[0] wajib ∈ [1, 10] | circuit (range assert 4-bit) |
| `fortifyCost` | **2 VFY** per FORTIFY yang ter-resolve | resolver platform (bukan circuit) |
| `fortifyBlock` | **6 VFY** — FORTIFY memblokir s.d. 6 dari ekstraksi masuk | resolver platform (bukan circuit) |

Resolver meng-cap transfer efektif pada *exposed balance* lawan (saldo yang
bisa dibelanjakan, dikurangi blokir fortify 6). Penting: **circuit tidak
meng-clip amount** — amount witness selalu persis params[0]; proof untuk
EXTRACT 10 terhadap lawan ber-saldo 1 atau 5 valid dan terverifikasi [FVX].
Jadi request besar tidak pernah merugikan; request kecil justru bisa
kehilangan seluruh hasil saat lawan fortify (5 − 6 ≤ 0).

## 4. Fungsi hash strategy commitment

**`commitment = Poseidon9([strategyParams[0], …, strategyParams[7], salt])`** —
circomlib Poseidon (BN128) atas 9 field element, params dulu, salt terakhir
[SRC source circuit §1; FVX; JM]. Bukan SHA-256, bukan Poseidon8.

- Representasi on-wire: field element sebagai `0x` + 64 hex lowercase
  [FVX `src/commitment.ts`, JM `src/poseidon.ts`]; di envelope muncul sebagai
  `strategyCommitment.hash`.
- Registrasi: Dashboard → My Agents → Edit agent → seksi Steal the VFY,
  **sebelum pairing Swiss Round 1**; dibekukan selama match, boleh diganti
  antar-ronde [SRC `docs/GAME.md`, /build §06].
- Vektor emas yang terverifikasi ulang di modul ini:
  - params `[10,0,0,0,0,0,0,0]`, salt `123456789` →
    `0x0bdd4ea66acf04d7ef79f45af72b709020c9269b8452dd6cab33355d866126cd` [JM] ✓
  - params `[10,0,0,0,0,0,0,0]`, salt `42` →
    `16038997112020182322173448379678790230845526951830566086947884141750627046316` [FVX] ✓
- Output circuit yang di STEAL-SPEC.md belum bernama kini teridentifikasi:
  **`proofTag = Poseidon3([matchId, turnNumber, circuitVersion])`**
  [SRC source §9 + `.sym`]. Urutan public signals (9):
  `[proofTag, commitment, matchId, turnNumber, selfBalance, opponentBalance,
  action, amount, circuitVersion]` — terverifikasi di uji lokal modul ini.
- Konversi `matchId` untuk witness & hash: UUID tanpa strip di-parse sebagai
  integer heksadesimal (uint128) [JM `circuitInputs.ts`, NES, SRC].

## 5. Semantik strategyParams[8]

Dari source circuit [SRC] (nama parameter asli berhasil dipulihkan):

| Indeks | Nama | Semantik |
|---|---|---|
| 0 | `extractAmount` | Jumlah EXTRACT; wajib ∈ [1, 10]. Nilai 0 membuat proof **mustahil** (assert circuit) |
| 1 | `fortifyThreshold` | FORTIFY bila `selfBalance < [1]` (strict) |
| 2 | `extractThreshold` | EXTRACT bila `opponentBalance > [2]` (strict) |
| 3 | `holdPriority` | ∈ {0, 1}; 1 = jangan pernah EXTRACT (HOLD mengalahkan EXTRACT, tapi **tidak** mengalahkan FORTIFY) |
| 4–7 | reserved | Wajib tepat 0 (constraint circuit) |

Aturan keputusan lengkap (prioritas ketat, ditegakkan circuit — aksi lain
tidak bisa di-proof):

```
if selfBalance < params[1]                       -> FORTIFY (amount 0)
elif opponentBalance > params[2] and params[3]==0 -> EXTRACT params[0]
else                                              -> HOLD (amount 0)
```

Template-nya `VfyPolicyProof(16, 10)`: komparator 16-bit, jadi threshold dan
balance aman di ≤ 65535. Circuit tidak memeriksa affordabilitas biaya fortify
(bisa FORTIFY di saldo 0) dan tidak tahu status fortified — semua itu urusan
resolver platform.

## 6. Rancangan strategi (yang diimplementasikan modul ini)

Konsekuensi desain yang paling penting: **strategi Steal = pilihan
(strategyParams, salt), bukan logika per-turn.** Circuit hanya mengizinkan
satu keluarga kebijakan di atas; "FORTIFY saat unggul" misalnya *tidak bisa
diekspresikan* — circuit fortify justru saat saldo kita rendah. Modul ini
(`src/strategy.mjs`) mengimplementasikan `decideAction` sebagai cermin persis
aturan circuit (termasuk batas strict `<` / `>`), divalidasi oleh uji
negatif: input aksi menyimpang membuat fullProve throw.

Profil default yang dipilih — `DEFAULT_PARAMS = [10, 30, 0, 0, 0, 0, 0, 0]`
(sama dengan yang dipakai [OSO] di kompetisi):

- **EXTRACT 10 (maksimum)** kapan pun lawan memegang saldo > 0: resolver
  meng-cap transfer ke exposed balance lawan, jadi meminta 10 tidak pernah
  lebih buruk dari meminta lebih kecil; melawan lawan yang fortify, 10 − 6 = 4
  tetap masuk sedangkan amount ≤ 6 bisa nol total.
- **FORTIFY hanya saat self < 30**: biaya 2 untuk memblokir maks 6 hanya
  impas bila lawan kemungkinan mengekstrak penuh dan saldo kita sudah
  tertekan; di atas 30, mengekstrak balik lebih bernilai.
- Alternatif konservatif disediakan sebagai `CONSERVATIVE_PARAMS =
  [5, 40, 20, 0, 0, 0, 0, 0]` — didokumentasikan, tapi secara ekspektasi lebih
  lemah (alasan di atas); keputusan akhir params + salt produksi adalah
  pilihan user saat registrasi commitment, dan salt **tidak** boleh
  di-commit ke repo publik mana pun.

Perilaku modul (`src/turn.mjs`, pola sama dengan handler Gatekeeper live):
verifikasi HMAC raw body → validasi envelope → cek `strategyCommitment.hash`
envelope == commitment kita → cek deadline → putuskan aksi → fullProve →
**verifikasi lokal terhadap VK resmi** → rakit respons bertanda tangan HMAC.
Semua kegagalan degrade ke HOLD tanpa proof (lantai aman: respons invalid
di-skor HOLD oleh platform, sedangkan proof invalid −2). Cache idempotensi
per (matchId, turn) mengembalikan respons identik pada retry platform.

## 7. Yang MASIH harus dikonfirmasi dari payload practice turn asli

Modul ini **belum** disambungkan ke agent live. Sebelum integrasi, satu
practice turn asli harus mengonfirmasi:

1. **Penempatan proof yang diterima platform** — di dalam `policyProof`
   (`proof`/`publicSignals`) vs top level (`proof`/`public_signals`), dan
   apakah mengirim keduanya ditoleransi. Ini satu-satunya titik di mana
   implementasi peserta yang kredibel saling berbeda.
2. **Payload request mentah pertama** — nama field persis seperti yang
   dikirim platform (terutama: apakah `turn`/`state.*` persis seperti skema
   gabungan §1, apakah ada field tambahan seperti `taskId`/`idempotencyKey`
   dari platform, dan format `deadlineAt`). Log payload mentah practice turn
   pertama adalah sumber kebenarannya.
3. **Format commitment saat registrasi dashboard** — apakah form Edit agent →
   Steal menerima `0x` + 64 hex persis seperti keluaran
   `computeCommitmentHex`, dan apakah hash yang kembali di envelope practice
   sama persis (huruf besar/kecil) dengan yang kita hitung.
4. **Perilaku resolver pada EXTRACT 10 vs saldo lawan kecil (1–9)** — proof-nya
   valid secara lokal, tapi hanya practice yang membuktikan platform
   meng-resolve-nya sebagai transfer ter-cap (bukan reject).
5. **Apakah respons practice mengharuskan `proofReference`** (alur Kurier:
   submit proof → job Finalized → reference) atau cukup proof + public_signals
   inline seperti Gatekeeper. /build menyebut proofReference "optional", tapi
   [SRC] memperlakukannya sebagai jalur utama.
6. **Toleransi timestamp/nonce** — seberapa ketat platform memeriksa
   `issuedAt`/nonce kadaluarsa di sisi request, dan apakah respons wajib
   memuat field tambahan di luar skema §1.

## 8. Status uji lokal (2026-11-15)

`node test/run-tests.mjs` → **12/12 lolos**:

- 2 vektor emas commitment (JM + FVX), 1 vektor proofTag, 1 vektor
  publicInputsHash — semua cocok bit-for-bit.
- `decideAction`: 10 pemeriksaan aturan termasuk batas strict, prioritas
  FORTIFY > EXTRACT, holdPriority, dan validasi params.
- fullProve + `groth16.verify` (VK resmi `vfy-policy_verification_key.json`)
  untuk 3 skenario turn: EXTRACT (100 vs 100), FORTIFY (25 vs 100),
  HOLD (100 vs 0) — termasuk pemeriksaan layout 9 public signals.
- Uji negatif: aksi menyimpang dari kebijakan → circuit menolak (tidak ada
  witness).
- End-to-end `handleTurn`: bentuk respons EXTRACT/HOLD (amount ter-omit untuk
  HOLD), hash cocok, dan mismatch commitment degrade ke HOLD tanpa proof.
