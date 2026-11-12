package main

import (
	"errors"
	"strconv"
	"strings"
)

type releaseVersion struct {
	parts       [3]uint32
	development bool
}

func parseReleaseVersion(value string) (releaseVersion, error) {
	var result releaseVersion
	if len(value) > 44 {
		return result, errors.New("invalid software version")
	}
	if strings.HasSuffix(value, "-dev") {
		result.development = true
		value = strings.TrimSuffix(value, "-dev")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return result, errors.New("invalid software version")
	}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return result, errors.New("invalid software version")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return result, errors.New("invalid software version")
			}
		}
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return result, errors.New("invalid software version")
		}
		result.parts[i] = uint32(number)
	}
	return result, nil
}
func checkUpgrade(candidate, current string) error {
	next, err := parseReleaseVersion(candidate)
	if err != nil {
		return err
	}
	previous, err := parseReleaseVersion(current)
	if err != nil {
		return err
	}
	for i := range next.parts {
		if next.parts[i] > previous.parts[i] {
			return nil
		}
		if next.parts[i] < previous.parts[i] {
			return errors.New("software downgrade rejected; use an explicit local rollback procedure")
		}
	}
	if next.development && !previous.development {
		return errors.New("software downgrade rejected; a development build precedes the same stable version")
	}
	return nil
}
