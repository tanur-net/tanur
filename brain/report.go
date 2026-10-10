// SPDX-License-Identifier: MPL-2.0

package brain

// Report is one client observation, sent by the engine's telemetry. It is part
// of the client-side (open) surface: the on-wire shape a client emits. The
// server-side collector that aggregates reports and decides what to burn (the
// steering policy) is withheld from the open release — see telemetry.go.
//
// It carries NO user identity: only a rotating per-session reporter token (for
// dedup), the operator network key, the endpoint id, the outcome, and whether
// the reporter's line was up at all. (CLAUDE.md rule 6: operator/result/time
// yes, person no.)
type Report struct {
	// Reporter is a rotating, non-identifying per-session token used only to
	// count DISTINCT reporters within a window. It is not persistent and not
	// tied to a user.
	Reporter string `json:"r"`
	// Network is the operator key (e.g. MCC/MNC), so blocking is judged per
	// operator, which is how Iran's filtering actually differs.
	Network string `json:"n"`
	// Endpoint is the endpoint id the report is about.
	Endpoint string `json:"e"`
	// OK is whether this endpoint worked for the reporter.
	OK bool `json:"ok"`
	// Control is whether the reporter's line was up at all (it reached some
	// control). A FAIL with Control=false means "line down", not "endpoint
	// blocked", and must not count toward burning.
	Control bool `json:"c"`
	// T is the client's unix time; the collector uses its own clock for windows.
}
