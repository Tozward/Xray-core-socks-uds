//go:build with_sing_tun && linux && !android

package singtun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type kernelHEVProcess struct {
	command *exec.Cmd
	ticks   float64
}

// The runner links the exact HEV library used by the APK and borrows child fd3,
// matching Android JNI's supplied no-virtio-header TUN descriptor. It does not
// create another interface or change the host's routing/DNS.
func benchmarkStartHEV(b *testing.B, fd int, ip4, ip6 netip.Addr, mtu, socksPort int, noJumbo bool) *kernelHEVProcess {
	b.Helper()
	binary := os.Getenv("XRAY_HEV_BENCHMARK_BINARY")
	if binary == "" {
		b.Skip("set XRAY_HEV_BENCHMARK_BINARY to the pinned HEV library runner")
	}
	ticks, err := strconv.ParseFloat(os.Getenv("XRAY_HEV_CLOCK_TICKS"), 64)
	if err != nil || ticks <= 0 {
		b.Fatal("XRAY_HEV_CLOCK_TICKS must be the host getconf CLK_TCK value")
	}
	directory := b.TempDir()
	offload := ""
	if noJumbo {
		offload = "  offload:\n    tso: false\n    uso: false\n    jumbo: false\n"
	}
	// Keep Android defaults, including its 64KiB TCP buffer. The second HEV
	// case explicitly disables jumbo; no-header Android defaults retain jumbo.
	config := fmt.Sprintf("tunnel:\n  mtu: %d\n  ipv4: %s\n  ipv6: '%s'\n%ssocks5:\n  address: 127.0.0.1\n  port: %d\n  udp: udp\nmisc:\n  tcp-read-write-timeout: 300000\n  udp-read-write-timeout: 60000\n  log-level: error\n", mtu, ip4, ip6, offload, socksPort)
	configPath := filepath.Join(directory, "hev.yml")
	if err = os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		b.Fatal(err)
	}
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		b.Fatal(err)
	}
	file := os.NewFile(uintptr(duplicate), "hev-tun")
	defer file.Close()
	logPath := filepath.Join(directory, "hev.log")
	log, err := os.Create(logPath)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = log.Close() })
	command := exec.Command(binary, configPath)
	command.ExtraFiles = []*os.File{file}
	command.Stdout, command.Stderr = log, log
	if err = command.Start(); err != nil {
		b.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	b.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				output, _ := os.ReadFile(logPath)
				b.Errorf("HEV exited: %v: %s", err, output)
			}
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			<-done
			b.Error("HEV did not stop after SIGINT")
		}
	})
	return &kernelHEVProcess{command: command, ticks: ticks}
}

func (h *kernelHEVProcess) cpuTime(b *testing.B) (float64, float64) {
	b.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", h.command.Process.Pid))
	if err != nil {
		b.Fatal("HEV CPU accounting: ", err)
	}
	user, system, err := hevProcessTicks(string(data))
	if err != nil {
		b.Fatal(err)
	}
	return float64(user) / h.ticks, float64(system) / h.ticks
}

func hevProcessTicks(data string) (uint64, uint64, error) {
	// comm is parenthesized and may contain spaces/parentheses. Fields after
	// its final ')' start at field3; utime/stime are fields14/15 of proc stat.
	end := strings.LastIndexByte(data, ')')
	if end < 0 {
		return 0, 0, fmt.Errorf("invalid HEV process stat")
	}
	fields := strings.Fields(data[end+1:])
	if len(fields) < 13 {
		return 0, 0, fmt.Errorf("incomplete HEV process stat")
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	return user, system, err
}

func TestHEVProcessTicks(t *testing.T) {
	user, system, err := hevProcessTicks("123 (hev (test)) S 1 2 3 4 5 6 7 8 9 10 110 220 0 0")
	if err != nil || user != 110 || system != 220 {
		t.Fatalf("process clock ticks: %d %d %v", user, system, err)
	}
	for _, data := range []string{"", "123 (hev) S", "123 (hev) S 1 2 3 4 5 6 7 8 9 10 x 220"} {
		if _, _, err = hevProcessTicks(data); err == nil {
			t.Fatal("invalid process stat accepted")
		}
	}
}
