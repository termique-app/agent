package security

// SourceStatus is the wire-safe status of one watched log source, reported
// to the API on the existing metrics-ingest payload (FR-4.3/D-6). It NEVER
// carries log contents — only the path and whether the source is being
// actively tailed. This is deliberately a separate, minimal type from
// Source: Source additionally carries Name (an internal matcher-selection
// detail with no reason to leave the agent process).
type SourceStatus struct {
	Path   string `json:"path"`
	Active bool   `json:"active"`
}

// SourcesToStatus converts the detected sources into their reportable
// status shape. All entries detected by DetectSources are ones the agent
// has successfully opened for tailing, so they are reported Active: true —
// there is currently no "detected but failed to open" state to distinguish
// (TailNewLines treats a since-deleted source as a skip, not a persistent
// failure worth reporting differently).
//
// Deliberately always returns a non-nil slice (empty, not nil, when sources
// is empty) — the caller reports this over a pointer so the wire payload
// can distinguish "capture enabled, zero sources detected" (an explicit
// empty array — the silent-misconfiguration case FR-4.3 exists to surface)
// from "capture disabled" (field omitted entirely, see client.ingestPayload).
func SourcesToStatus(sources []Source) []SourceStatus {
	statuses := make([]SourceStatus, len(sources))
	for i, s := range sources {
		statuses[i] = SourceStatus{Path: s.Path, Active: true}
	}
	return statuses
}
