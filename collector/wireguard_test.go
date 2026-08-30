package collector

import (
	"testing"
)

func TestCollectWireguardParser(t *testing.T) {
	t.Parallel()

	mock := `netip-wg2	uP60yjQUtQD96mU=	dfn0VFdEqFL821Q=	38778	25
netip-wg2	T0IgWvAmzrZ7yKDXtgDM=	(none)	1.2.3.4:58573	10.30.1.2/32	1711837161	10500312	266158328	23
netip-wg2	LabCXRBFxp9ee7VYuXV4=	(none)	(none)	10.30.1.3/32	0	0	0	23
netip-wg2	jl3npy2NI1XmSel+owWU=	22M+eszE4Pa8=	(none)	10.30.1.4/32	0	0	0	23
netip-wg2	kAet9yOKeZzziruZKp0o=	(none)	1.2.3.4:64741	10.30.1.6/32	1711843584	73085528	458317140	23
netip-wg2	+RjTUw99rwUPycCfgHWM=	(none)	1.2.3.4:53683	10.30.1.5/32	1711797944	692	349292	23
netip-wg1	APeqSMGr0oazroIZcskk=	122M+eszE4Pa8U0=	38686	25
netip-wg1	PvEZYvPpojoZMil5F6kI=	(none)	4.3.2.1:60397	10.0.0.2/32	1711850994	51836	26288	25
`

	c := new(Collector)
	cwp := c.collectWireguardParser([]byte(mock))
	if len(cwp) != 5 {
		t.Fatal("wrong amount")
	}
	if cwp[0].Peer != "T0IgWvAmzrZ7yKDXtgDM=" || cwp[4].Peer != "+RjTUw99rwUPycCfgHWM=" {
		t.Fatal("wrong parsed")
	}
}
