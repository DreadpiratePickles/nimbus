package core

import "testing"

// Defect 10c (verify-4 D8): a set of public CIDRs whose union covers at least half of the
// address family is wide, not narrow: 0.0.0.0/1 + 128.0.0.0/1 is the whole IPv4 internet.
func TestV4ExposureWidthCIDRUnion(t *testing.T) {
	cases := []struct {
		srcs []string
		want string
	}{
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, ExposureWide},
		{[]string{"128.0.0.0/1"}, ExposureWide}, // exactly 50 %
		{[]string{"0.0.0.0/2", "64.0.0.0/2"}, ExposureWide},
		{[]string{"64.0.0.0/2", "64.0.0.0/3", "128.0.0.0/3"}, ExposureNarrow}, // 25 % + 12.5 % (overlap counted once)
		{[]string{"198.51.100.0/24"}, ExposureNarrow},
		{[]string{"::/1", "8000::/1"}, ExposureWide},
		{[]string{"2001:db8::/32"}, ExposureNarrow},
	}
	for _, c := range cases {
		if got := ExposureWidth(c.srcs, nil); got != c.want {
			t.Errorf("ExposureWidth(%v) = %s, want %s", c.srcs, got, c.want)
		}
	}
}
