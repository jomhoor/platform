// Package zkp implements query-proof verification for POST /v1/assertions/zk.
//
// Design (see docs/SSO/plan.txt M5 item 4):
//
//   - Wallet runs the existing Rarimo `queryIdentity` (Circom/Groth16 passport)
//     or `queryIdentity_inid_ca` (Noir/UltraPlonk INID) circuit with
//     `event_id = sso_event_id` and a selector that reveals at minimum the
//     nullifier.
//
//   - sso-svc verifies each proof by calling the circuit's on-chain verifier
//     contract via JSON-RPC eth_call. This keeps verification proving-system
//     agnostic (UltraPlonk, Groth16, …) and reuses our already-deployed
//     sovereign verifier contracts (e.g. NoirTD1Verifier) as the single
//     source of truth — the same contract code that voting trusts.
//
//   - sso-svc additionally pins event_id (global), optionally validates
//     `registration_smt_root` against the on-chain RegistrationSMT
//     (isRootValid), and inserts an assertion row with
//     nullifier_hash = pub_signals[idx].
//
//   - Nullifiers are NOT stored on the registration contract. "Registered" is
//     proven implicitly by the Merkle inclusion check inside the circuit; the
//     SMT-root check here binds that inclusion proof to a recent on-chain root.
//
// Multi-circuit (Iranian + INID + international passport variants):
//
//   The wallet identifies its document class on scan (Variant-A passport,
//   Variant-B passport, INID, German ECDSA, …) and sends a stable
//   `circuit_id` string with the proof. Each entry in `Circuits` carries its
//   own on-chain verifier address and pub-signal index layout. Adding a new
//   variant = drop a deployed verifier address into config; zero code change.
//
// Privacy invariants (M2.5):
//
//   - Handler returns 200 with no body. RPs read assertion status via
//     /v1/tokens/validate. No assertion data leaks into JWT claims.
//   - assertion_type stays "zk_verified" for ALL circuits. The circuit_id is
//     recorded in `assertions.source` for audit only — never surfaced to RPs.
package zkp

import (
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

// CircuitConfig describes one verifiable circuit class (e.g. Iranian Variant-A
// passport, Iranian INID, German ECDSA passport, …).
type CircuitConfig struct {
	// VerifierAddress is the on-chain verifier contract for this circuit
	// (e.g. our deployed NoirTD1Verifier). sso-svc calls verify(bytes,bytes32[])
	// via eth_call to validate each proof. The wallet uses the same proving
	// system the contract expects (UltraPlonk for Noir, Groth16 for Circom).
	VerifierAddress string `fig:"verifier_address,required"`

	// Pub-signal indices for this circuit. Defaults match Rarimo queryIdentity
	// (passport) layout; INID uses a different layout (23 signals vs 24).
	NullifierIndex int `fig:"nullifier_index"`
	EventIDIndex   int `fig:"event_id_index"`
	SMTRootIndex   int `fig:"smt_root_index"`
}

// Config holds the sso-svc query-proof verification settings.
type Config struct {
	// Enabled gates the POST /v1/assertions/zk handler. When false, the handler
	// returns 404 — useful for staged rollout.
	Enabled bool `fig:"enabled"`

	// EventID is the decimal-string-encoded field element the wallet must use
	// as the circuit `event_id` input. Pinning binds proofs to sso-svc and
	// prevents cross-service replay. Global across all circuits.
	EventID string `fig:"event_id,required"`

	// AssertionTTL is how long an inserted assertion remains live before
	// `/v1/tokens/validate` stops reporting `zk_verified=true`.
	AssertionTTL string `fig:"assertion_ttl,required"`

	// RegistrationSMT on-chain root check. Optional in dev — when
	// RegistrationSMTAddr is empty the verifier skips the root check.
	// Required in production. Same RegistrationSMT for all circuits (one
	// identity graph).
	RPCURL              string `fig:"rpc_url"`
	RegistrationSMTAddr string `fig:"registration_smt_address"`

	// Circuits is the registry of supported circuit classes keyed by stable
	// `circuit_id` string. The wallet sends this id with each proof. Entries
	// without a corresponding wallet circuit detector are ignored at runtime;
	// missing-from-config circuit_ids on requests yield 400.
	Circuits map[string]CircuitConfig `fig:"circuits"`
}

// Zkper is composed into the service Config and exposes the verifier.
type Zkper interface {
	ZKP() *Verifier
}

type zkper struct {
	once   comfig.Once
	getter kv.Getter
}

func NewZkper(getter kv.Getter) Zkper {
	return &zkper{getter: getter}
}

func (z *zkper) ZKP() *Verifier {
	return z.once.Do(func() interface{} {
		raw := kv.MustGetStringMap(z.getter, "zkp")
		// Fast-path: zkp disabled (local dev). The "circuits" map type has no
		// figure hook registered, so even parsing an empty map would fail. Short-circuit.
		if enabled, _ := raw["enabled"].(bool); !enabled {
			v, err := NewVerifier(Config{Enabled: false})
			if err != nil {
				panic(errors.WithMessage(err, "failed to construct disabled zkp verifier"))
			}
			return v
		}
		cfg := Config{}
		if err := figure.Out(&cfg).From(raw).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out zkp config"))
		}
		v, err := NewVerifier(cfg)
		if err != nil {
			panic(errors.WithMessage(err, "failed to construct zkp verifier"))
		}
		return v
	}).(*Verifier)
}
