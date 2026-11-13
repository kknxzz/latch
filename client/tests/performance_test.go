//go:build darwin || linux

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"latch.local/client/internal/app"
	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
	"latch.local/client/internal/network"
	"latch.local/client/internal/protocol"
)

type processSample struct {
	RSSBytes          int64
	CPUSeconds        float64
	ResolutionSeconds float64
}
type idleMeasurement struct {
	WindowSeconds        float64 `json:"window_seconds"`
	ClientRSSBytes       int64   `json:"client_rss_bytes"`
	ServerRSSBytes       int64   `json:"server_rss_bytes"`
	ClientCPUPercent     float64 `json:"client_one_core_cpu_percent"`
	ServerCPUPercent     float64 `json:"server_one_core_cpu_percent"`
	CPUResolutionSeconds float64 `json:"cpu_resolution_seconds"`
}
type connectionMeasurement struct {
	Count                      int     `json:"count"`
	BaselineRSSBytes           int64   `json:"baseline_rss_bytes"`
	ConnectedRSSBytes          int64   `json:"connected_rss_bytes"`
	ObservedBytesPerConnection float64 `json:"observed_bytes_per_connection"`
	P50Microseconds            float64 `json:"p50_microseconds"`
	P95Microseconds            float64 `json:"p95_microseconds"`
}
type messageMeasurement struct {
	PayloadBytes       int     `json:"payload_bytes"`
	Offered            int     `json:"offered"`
	Delivered          int     `json:"delivered"`
	RateLimited        int     `json:"rate_limited"`
	WindowSeconds      float64 `json:"window_seconds"`
	DeliveredPerSecond float64 `json:"delivered_per_second"`
	P50Microseconds    float64 `json:"p50_microseconds"`
	P95Microseconds    float64 `json:"p95_microseconds"`
}
type performanceReport struct {
	Time              string                `json:"time_utc"`
	OS                string                `json:"os"`
	Arch              string                `json:"arch"`
	Go                string                `json:"go"`
	LogicalCPUs       int                   `json:"logical_cpus"`
	Transport         string                `json:"transport"`
	ClientBinaryBytes int64                 `json:"client_binary_bytes"`
	ServerBinaryBytes int64                 `json:"server_binary_bytes"`
	Idle              idleMeasurement       `json:"idle"`
	Connections       connectionMeasurement `json:"connections"`
	Messages          []messageMeasurement  `json:"messages"`
}

func releaseBinary(t *testing.T, ctx context.Context, dir, name string) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), name)
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", "-buildid= -s -w", "-o", output, "./cmd/"+name)
	cmd.Dir = dir
	if name == "latch-server" {
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	}
	if result, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("optimized build: %v: %s", err, result)
	}
	return output
}
func durationPercentile(values []time.Duration, p float64) float64 {
	copyOf := append([]time.Duration(nil), values...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i] < copyOf[j] })
	if len(copyOf) == 0 {
		return 0
	}
	index := max(0, int(math.Ceil(float64(len(copyOf))*p))-1)
	return float64(copyOf[index]) / float64(time.Microsecond)
}
func sample(t *testing.T, pid int) processSample {
	t.Helper()
	value, err := sampleProcess(pid)
	if err != nil {
		t.Fatal("process measurement failed", err)
	}
	return value
}

// Opt-in measurement of real binaries and the production network/app/crypto
// path. Reports contain numbers only; no identities, keys or message bodies.
func TestPerformanceReport(t *testing.T) {
	if os.Getenv("LATCH_PERFORMANCE") != "1" {
		t.Skip("explicit runtime measurement only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base, err := os.MkdirTemp("/tmp", "latch-benchmark-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	serverBinary := releaseBinary(t, ctx, "../../server", "latch-server")
	clientBinary := releaseBinary(t, ctx, "..", "latch")
	report := performanceReport{Time: time.Now().UTC().Format(time.RFC3339), OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), LogicalCPUs: runtime.NumCPU(), Transport: "Explicit loopback development WS; E2EE enabled; optimized development binaries without publisher root"}
	for path, dst := range map[string]*int64{clientBinary: &report.ClientBinaryBytes, serverBinary: &report.ServerBinaryBytes} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		*dst = info.Size()
	}
	const count = 100
	ids := make([]identity.Identity, count)
	t.Cleanup(func() {
		for i := range ids {
			ids[i].Clear()
		}
	})
	var inventory []struct {
		UUID      string `json:"uuid"`
		PublicKey []byte `json:"public_key"`
		Nickname  string `json:"nickname"`
	}
	for i := range ids {
		ids[i], err = identity.Generate("11111111-1111-4111-8111-111111111111")
		if err != nil {
			t.Fatal(err)
		}
		inventory = append(inventory, struct {
			UUID      string `json:"uuid"`
			PublicKey []byte `json:"public_key"`
			Nickname  string `json:"nickname"`
		}{ids[i].UUID, ids[i].PublicKey, fmt.Sprintf("Bench %d", i)})
	}
	input, state := filepath.Join(base, "public-inventory.json"), filepath.Join(base, "server")
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	prepare := exec.CommandContext(ctx, "go", "test", "-count=1", "-run=^TestPreparePerformanceFixture$", "./tests")
	prepare.Dir = "../../server"
	prepare.Env = append(os.Environ(), "LATCH_PERF_FIXTURE_INPUT="+input, "LATCH_PERF_FIXTURE_STATE="+state)
	if output, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("synthetic fixture preparation: %v: %s", err, output)
	}
	sid, err := os.ReadFile(input + ".server-id")
	if err != nil {
		t.Fatal(err)
	}
	for i := range ids {
		ids[i].ServerID = string(sid)
	}
	server := startServer(t, ctx, serverBinary, state, "127.0.0.1:0")
	serverURL := "http://" + serverAddress(t, server)
	terminal := startClient(t, ctx, clientBinary, serverBinary, state, serverURL, "Idle Benchmark", filepath.Join(base, "terminal"))
	children, err := exec.CommandContext(ctx, "pgrep", "-P", strconv.Itoa(terminal.cmd.Process.Pid)).Output()
	if err != nil || len(strings.Fields(string(children))) != 1 {
		t.Fatal("could not identify the actual terminal client process", err)
	}
	clientPID, err := strconv.Atoi(strings.TrimSpace(string(children)))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	clientStart, serverStart := sample(t, clientPID), sample(t, server.cmd.Process.Pid)
	started := time.Now()
	time.Sleep(10 * time.Second)
	clientEnd, serverEnd := sample(t, clientPID), sample(t, server.cmd.Process.Pid)
	window := time.Since(started).Seconds()
	report.Idle = idleMeasurement{WindowSeconds: window, ClientRSSBytes: clientEnd.RSSBytes, ServerRSSBytes: serverEnd.RSSBytes, ClientCPUPercent: (clientEnd.CPUSeconds - clientStart.CPUSeconds) / window * 100, ServerCPUPercent: (serverEnd.CPUSeconds - serverStart.CPUSeconds) / window * 100, CPUResolutionSeconds: max(clientEnd.ResolutionSeconds, serverEnd.ResolutionSeconds)}
	terminal.write(t, "/quit\r")
	terminal.out.wait(t, "LATCH_TEST_CLIENT_EXIT:0")
	terminal.write(t, "\n")
	select {
	case <-terminal.done:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal client did not finish")
	}
	time.Sleep(time.Second)
	baseline := sample(t, server.cmd.Process.Pid)
	var connections []*network.Connection
	var clients []*network.Client
	var durations []time.Duration
	closePeers := func() {
		for _, connection := range connections {
			connection.Close()
		}
		for _, client := range clients {
			client.Close()
		}
		connections = nil
		clients = nil
	}
	defer closePeers()
	for i := range ids {
		c := config.Config{ServerURL: serverURL, Endpoint: "/c/", Development: true, ServerID: string(sid), IdentityBackend: "file", Nickname: inventory[i].Nickname, Enrolled: true}
		client := network.New(c)
		clients = append(clients, client)
		started := time.Now()
		connection, err := client.Connect(ctx, ids[i])
		if err != nil {
			t.Fatal("capacity connection rejected", i, err)
		}
		durations = append(durations, time.Since(started))
		connections = append(connections, connection)
	}
	time.Sleep(time.Second)
	connected := sample(t, server.cmd.Process.Pid)
	report.Connections = connectionMeasurement{Count: count, BaselineRSSBytes: baseline.RSSBytes, ConnectedRSSBytes: connected.RSSBytes, ObservedBytesPerConnection: float64(connected.RSSBytes-baseline.RSSBytes) / count, P50Microseconds: durationPercentile(durations, .5), P95Microseconds: durationPercentile(durations, .95)}
	closePeers()
	time.Sleep(time.Second)
	for _, size := range []int{128, 4096} {
		report.Messages = append(report.Messages, measureMessages(t, ctx, serverURL, ids[:2], size))
	}
	server.stop(t, syscall.SIGTERM)
	if server.err != nil {
		t.Fatal("measured gateway did not shut down cleanly", server.err)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("LATCH_PERF_REPORT"); path != "" {
		if !filepath.IsAbs(path) {
			t.Fatal("report path must be absolute")
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Write(append(encoded, '\n'))
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal("report write failed", err, closeErr)
		}
	}
	t.Log(string(encoded))
}

type measuredSender struct {
	connection  *network.Connection
	lastMessage string
}

func (s *measuredSender) Send(kind string, body any) (string, error) {
	id, err := s.connection.Send(kind, body)
	if kind == "message.send" {
		s.lastMessage = id
	}
	return id, err
}

func measureMessages(t *testing.T, ctx context.Context, url string, ids []identity.Identity, payloadBytes int) messageMeasurement {
	t.Helper()
	var connections [2]*network.Connection
	var models [2]*app.Model
	var senders [2]*measuredSender
	for i := range connections {
		client := network.New(config.Config{ServerURL: url, Endpoint: "/c/", Development: true, ServerID: ids[i].ServerID, IdentityBackend: "file", Nickname: fmt.Sprintf("Bench %d", i), Enrolled: true})
		defer client.Close()
		connection, err := client.Connect(ctx, ids[i])
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		connections[i] = connection
		senders[i] = &measuredSender{connection: connection}
		models[i] = app.New(ids[i], url, fmt.Sprintf("Bench %d", i), senders[i], nil)
		defer models[i].Close()
	}
	handle := func(index int, event network.Event) {
		t.Helper()
		if event.Err != nil {
			t.Fatal("benchmark connection failed", event.Err)
		}
		if err := models[index].Handle(event.Message); err != nil {
			t.Fatal("production state machine failed", err)
		}
	}
	pump := func(done func() bool) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for !done() {
			select {
			case event := <-connections[0].Events():
				handle(0, event)
			case event := <-connections[1].Events():
				handle(1, event)
			case <-timer.C:
				t.Fatal("benchmark state transition timed out")
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	if err := models[0].Input("/create"); err != nil {
		t.Fatal(err)
	}
	pump(func() bool { return models[0].Snapshot().Ready })
	if err := models[1].Input("/join " + models[0].Snapshot().RoomID); err != nil {
		t.Fatal(err)
	}
	pump(func() bool {
		return models[0].Snapshot().Ready && models[1].Snapshot().Ready && len(models[0].Snapshot().Members) == 2
	})
	result := messageMeasurement{PayloadBytes: payloadBytes}
	var latencies []time.Duration
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	warmUntil := time.Now().Add(4 * time.Second)
	finish := warmUntil.Add(10 * time.Second)
	sequence := 0
	var measuredStart time.Time
	for time.Now().Before(finish) {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		sequence++
		prefix := fmt.Sprintf("benchmark-%06d ", sequence)
		text := prefix + strings.Repeat("x", payloadBytes-len(prefix))
		start := time.Now()
		measured := !start.Before(warmUntil)
		if measured && measuredStart.IsZero() {
			measuredStart = start
		}
		if err := models[0].Input(text); err != nil {
			t.Fatal(err)
		}
		requestID := senders[0].lastMessage
		ack, delivered, rejected := false, false, false
		deadline := time.NewTimer(5 * time.Second)
		for !ack || (!delivered && !rejected) {
			select {
			case event := <-connections[0].Events():
				handle(0, event)
				if event.Message.RequestID == requestID {
					ack = true
					if event.Message.Type == "error" {
						var failure protocol.Error
						if protocol.Strict(event.Message.Body, &failure) != nil || failure.Code != "RATE_LIMITED" {
							t.Fatal("unexpected relay rejection")
						}
						rejected = true
					}
				}
			case event := <-connections[1].Events():
				handle(1, event)
				if event.Message.Type == "message.deliver" {
					snapshot := models[1].Snapshot()
					if len(snapshot.Lines) == 0 || snapshot.Lines[len(snapshot.Lines)-1].Text != text {
						t.Fatal("encrypted delivery mismatch")
					}
					delivered = true
					if measured {
						latencies = append(latencies, time.Since(start))
					}
				}
			case <-deadline.C:
				t.Fatal("encrypted delivery timed out")
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		deadline.Stop()
		if measured {
			result.Offered++
			if rejected {
				result.RateLimited++
			} else {
				result.Delivered++
			}
		}
	}
	result.WindowSeconds = time.Since(measuredStart).Seconds()
	result.DeliveredPerSecond = float64(result.Delivered) / result.WindowSeconds
	result.P50Microseconds = durationPercentile(latencies, .5)
	result.P95Microseconds = durationPercentile(latencies, .95)
	return result
}
