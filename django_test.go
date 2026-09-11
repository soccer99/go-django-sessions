package go_django_sessions

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// djangoVersions lists the pip specs that the tests run against.
// The last entry has no upper bound, so it is always the latest release.
var djangoVersions = []string{"django>=4.2,<4.3", "django>=5.2,<5.3", "django"}

// runDjango runs testdata/django_session.py with the given Django version through uv.
func runDjango(t *testing.T, spec string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is not installed")
	}
	base := []string{"run", "-q", "--no-project", "--python", "3.12", "--with", spec,
		"python", "testdata/django_session.py", opts.SecretKey}
	out, err := exec.Command("uv", append(base, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("uv %s: %v\n%s", spec, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestDjangoVersions(t *testing.T) {
	want, _ := json.Marshal(longData)
	for _, spec := range djangoVersions {
		t.Run(spec, func(t *testing.T) {
			t.Logf("Django %s", runDjango(t, spec, "version"))

			// Django encodes, Go decodes.
			got, err := DecodeSession(runDjango(t, spec, "encode", string(want)), opts)
			if err != nil || !reflect.DeepEqual(got, longData) {
				t.Fatalf("Go decode of Django output: %v %v", got, err)
			}

			// Go encodes, Django decodes.
			enc, err := EncodeSession(longData, opts)
			if err != nil {
				t.Fatal(err)
			}
			var back map[string]any
			if err := json.Unmarshal([]byte(runDjango(t, spec, "decode", enc)), &back); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(back, longData) {
				t.Fatalf("Django decode of Go output: %v", back)
			}
		})
	}
}
