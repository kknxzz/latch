package tests

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func sampleProcess(pid int) (processSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return processSample{}, err
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return processSample{}, fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 22 {
		return processSample{}, fmt.Errorf("short process stat")
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return processSample{}, err
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return processSample{}, err
	}
	rss, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return processSample{}, err
	}
	clock, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		return processSample{}, err
	}
	ticks, err := strconv.ParseFloat(strings.TrimSpace(string(clock)), 64)
	if err != nil || ticks <= 0 {
		return processSample{}, fmt.Errorf("invalid clock frequency")
	}
	return processSample{RSSBytes: rss * int64(os.Getpagesize()), CPUSeconds: float64(user+system) / ticks, ResolutionSeconds: 1 / ticks}, nil
}
