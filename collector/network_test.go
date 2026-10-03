package collector

import (
	"os"
	"testing"
)

func TestNetDevHandler(t *testing.T) {
	t.Parallel()

	pdn := t.TempDir() + "/proc-dev-net"

	err := os.WriteFile(pdn, []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
veth77d9db2: 47357203888 10775223    0    0    0     0          0         0 47214455584 7863327    0    0    0     0       0          0
docker0: 122565476666753 76089192142    0    0    0     0          0         0 129085535022779 72360055981    0    0    0     0       0          0
  eth0: 130547025418396 123074346864    0    0    0     0          0         0 123199978882158 72355179743    0    0    0     0       0          0
vethd33d0aa: 3335805246  960475    0    0    0     0          0         0 3287346942  871750    0    0    0     0       0          0
  cni0:  188496    3341    0    0    0     0          0         0   279257    3731    0    0    0     0       0          0
vethda183ff:  588648    4388    0    0    0     0          0         0   998804    6618    0    0    0     0       0          0
   wg0: 1755409256 7637558   12    0    0    12          0         0 23798324936 18964339    0 7530    0     0       0          0
veth8f0d716: 1798186740  965060    0    0    0     0          0         0 152870472  943566    0    0    0     0       0          0
docker_gwbridge:       0       0    0    0    0     0          0         0     2560      24    0    0    0     0       0          0
    lo: 14852599902362 40985373522    0    0    0     0          0         0 14852599902362 40985373522    0    0    0     0       0          0
vethe642356:       0       0    0    0    0     0          0         0   343736    4908    0    0    0     0       0          0
`), os.ModePerm)

	if err != nil {
		t.Fatal(err)
	}

	c := new(Collector)
	c.netDevHandler(pdn)

	if e, ok := c.data.NetworkStats["eth0"]; ok {
		if e.BytesRx != 0 || e.PacketsRx != 0 {
			t.Fatal("uncorrected rx")
		}
		if e.BytesTx != 0 || e.PacketsTx != 0 {
			t.Fatal("uncorrected tx")
		}
	} else {
		t.Fatal("not exists eth")
	}

	t.Logf("%+v", c.data.NetworkStats)
}
