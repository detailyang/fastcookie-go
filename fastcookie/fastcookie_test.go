package fastcookie

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFuzzedCookie(t *testing.T) {
	var fc FastCookie

	u := []byte("httponly")
	fc.Parse([][]byte{u})
	require.Equal(t, "; HttpOnly", fc.String())

	u = []byte(`; max-age=2`)
	fc.Reset()
	fc.Parse([][]byte{u})
	require.Equal(t, "; max-age=2", fc.String())
}

func TestWantCookie(t *testing.T) {
	c := []byte(`cookie-9=i3e01nf61b6t23bvfmplnanol3; Path=/restricted/; Domain=exAmple.com; Expires=Tue, 10 Nov 2009 23:00:00 GMT; Max-Age=3600`)

	var fc FastCookie
	ParseCookie(&fc, [][]byte{c})
	require.Equal(t, 3600, fc.GetMaxAge())
	require.Equal(t, "2009-11-10 23:00:00 +0000 UTC", fc.GetExpires().String())
	require.Equal(t, "/restricted/", string(fc.GetPath()))
	require.Equal(t, "example.com", string(fc.GetDomain()))
	d, ok := fc.Get([]byte("cookie-9"))
	require.Equal(t, true, ok)
	require.Equal(t, "i3e01nf61b6t23bvfmplnanol3", string(d))
}

func TestCookie(t *testing.T) {
	var fc FastCookie
	for _, tt := range []struct {
		Input string
		Name  string
		Value string
	}{
		{
			"cookie-1=v$1",
			"cookie-1",
			"v$1",
		},
		{
			"cookie-2=two; Max-Age=3600",
			"cookie-2",
			"two",
		},
		{
			"empty-value=",
			"empty-value",
			"",
		},
		{
			"cookie-15=samesite-none; SameSite=None",
			"cookie-15",
			"samesite-none",
		},
		{
			"cookie-10=expiring-1601;",
			"cookie-10",
			"expiring-1601",
		},
	} {
		fc.Reset()
		ParseCookie(&fc, [][]byte{[]byte(tt.Input)})
		d, ok := fc.Get([]byte(tt.Name))
		require.Equal(t, true, ok)
		require.Equal(t, tt.Value, string(d))
	}
}
