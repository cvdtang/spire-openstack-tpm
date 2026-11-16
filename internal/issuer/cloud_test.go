package issuer

import (
	"encoding/json"
	"testing"
)

// Ensures a node's EK record is read from its inspection data, telling absent and malformed apart.
func TestEKFromPluginData(t *testing.T) {
	for name, c := range map[string]struct {
		data    string
		want    string
		invalid bool
	}{
		"inspected": {data: `{"openstack_tpm": {"tpm_ek_sha256": "0123abcd", "tpm_version": "2.0"}}`, want: "0123abcd"},
		// There is no record when the node was inspected without the collector or the collector found no TPM.
		"no collector":   {data: `{"other": {}}`},
		"no plugin data": {data: `{}`},
		"no EK":          {data: `{"openstack_tpm": {"error": "no TPM"}}`},
		"null EK":        {data: `{"openstack_tpm": {"tpm_ek_sha256": null}}`},
		// A record that is not the collector's is an error, not an absent record.
		"wrong type":   {data: `{"openstack_tpm": {"tpm_ek_sha256": 7}}`, invalid: true},
		"not a report": {data: `{"openstack_tpm": "0123abcd"}`, invalid: true},
	} {
		var data map[string]json.RawMessage
		if err := json.Unmarshal([]byte(c.data), &data); err != nil {
			t.Fatal(err)
		}
		ek, err := ekFromPluginData(data)
		if (err != nil) != c.invalid || ek != c.want {
			t.Errorf("%s: %q, %v", name, ek, err)
		}
	}
}
