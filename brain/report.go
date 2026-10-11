// SPDX-License-Identifier: MPL-2.0

package brain

// Report is one client observation — the only thing that leaves a device for the
// telemetry loop. It carries NO user identity (CLAUDE.md rule 6): a rotating,
// non-identifying reporter token, the operator key (overridden server-side), the
// endpoint id, the outcome, where a failure happened, and why. No user, no
// account, no IP, no destination, no client timestamp. See docs/telemetry-privacy.md.
type Report struct {
	// Reporter is a rotating, non-identifying token used only to count DISTINCT
	// reporters within a window (for burn voting). It is random, not derived from
	// anything about the user or device, not persisted, and the engine rolls it
	// on a fixed epoch (engine.reporterEpoch) so reports are linkable only within
	// that epoch, never across the whole life of a long-running engine.
	Reporter string `json:"r"`
	// Network is the operator key, so blocking is judged per operator (how Iran's
	// filtering actually differs). The client cannot fill this reliably — on iOS
	// it is unreadable — so the collector overrides it server-side from the source
	// IP. Kept on the wire only as a fallback.
	Network string `json:"n,omitempty"`
	// Endpoint is the endpoint id the report is about.
	Endpoint string `json:"e"`
	// OK is whether this endpoint worked for the reporter.
	OK bool `json:"ok"`
	// Control is whether the reporter's line was up at all (it reached some
	// control). A FAIL with Control=false means "line down", not "endpoint
	// blocked", and must not count toward burning.
	Control bool `json:"c"`
	// Stage is where the outcome was decided: "tcp", "tls", "door", "inner" or ""
	// (unknown). It tells the dashboard WHERE a block happens — a research signal,
	// not a per-user fact. omitempty: a client that does not classify sends nothing.
	Stage string `json:"s,omitempty"`
	// Reason is a FIXED, non-identifying code for WHY the failure happened
	// ("timeout", "reset", "refused", "unreachable", "closed", "tls", "cert",
	// "protocol", "canceled", "other"), from ReasonOf — never the raw error text,
	// which could carry a destination. Paired with Stage (where), it answers "why
	// didn't it connect?" while keeping rule 6. omitempty on success/unclassified.
	Reason string `json:"rs,omitempty"`
	// The client sends NO timestamp: the collector stamps arrival with its own
	// clock. Keeping time server-side is both a privacy and an anti-fingerprint
	// choice — no precise client clock on the wire.
}
