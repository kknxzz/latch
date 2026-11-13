package tests

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func sampleProcess(pid int) (processSample, error) {
	output, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "rss=", "-o", "time=").Output()
	if err != nil {
		return processSample{}, err
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 {
		return processSample{}, fmt.Errorf("unexpected process sample")
	}
	rss, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return processSample{}, err
	}
	var seconds float64
	for _, part := range strings.Split(fields[1], ":") {
		value, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return processSample{}, err
		}
		seconds = seconds*60 + value
	}
	return processSample{RSSBytes: rss * 1024, CPUSeconds: seconds, ResolutionSeconds: .01}, nil
}
