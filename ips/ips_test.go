package ips

import (
	"net"
	"testing"
)

func TestCFIPs(t *testing.T) {
	cidrs := CFIPs()
	if len(cidrs) == 0 {
		t.Fatal("CFIPs() returned an empty list")
	}
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			t.Errorf("CFIPs() returned invalid CIDR %q: %v", cidr, err)
		}
	}
}
