package baseline

import "testing"

func FuzzParseReportHeader(f *testing.F) {
	f.Add([]byte(`{"schema_version":"1","tool_version":"dev","report_kind":"tls_scan","scope_kind":"explicit","scope_description":"targets","generated_at":"2026-04-01T00:00:00Z","scope":{"scope_kind":"explicit","input_kind":"targets"}}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Helper()
		_, _ = ParseReportHeader(data)
	})
}
