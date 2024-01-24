package models

import (
	"errors"
	"testing"
	"time"
)

func TestDurationToString(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{duration: 0, expected: "0s"},
		{duration: time.Second, expected: "1s"},
		{duration: time.Minute, expected: "1m"},
		{duration: time.Hour, expected: "1h"},
		{duration: 24 * time.Hour, expected: "1d"},
		{duration: 7 * 24 * time.Hour, expected: "1w"},
		{duration: 52 * 7 * 24 * time.Hour, expected: "1y"},
		{duration: 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, expected: "1w3d23h47m16s854ms775us807ns"},
		{duration: 250*52*7*24*time.Hour + 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, expected: "250y1w3d23h47m16s854ms775us807ns"},
		{duration: 123 * time.Millisecond, expected: "123ms"},
		{duration: 456 * time.Microsecond, expected: "456us"},
		{duration: 789 * time.Nanosecond, expected: "789ns"},
		{duration: 1 * time.Microsecond, expected: "1us"},
		{duration: 1 * time.Millisecond, expected: "1ms"},
		{duration: -1 * time.Second, expected: "-1s"}, // Additional test case for negative duration
	}

	for _, test := range tests {
		result := DurationToString(test.duration)
		if result != test.expected {
			t.Errorf("DurationToString(%v) = %s, expected %s", test.duration, result, test.expected)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		err      error
	}{
		{input: "0", expected: 0, err: nil},
		{input: "1s", expected: time.Second, err: nil},
		{input: "1m", expected: time.Minute, err: nil},
		{input: "1h", expected: time.Hour, err: nil},
		{input: "1d", expected: 24 * time.Hour, err: nil},
		{input: "1w", expected: 7 * 24 * time.Hour, err: nil},
		{input: "1y", expected: 52 * 7 * 24 * time.Hour, err: nil},
		{input: "1w3d23h47m16s854ms775us807ns", expected: 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, err: nil},
		{input: "250y1w3d23h47m16s854ms775us807ns", expected: 250*52*7*24*time.Hour + 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, err: nil},
		{input: "293y1w3d23h47m16s854ms775us807ns", expected: 293*52*7*24*time.Hour + 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, err: nil},
		{input: "123ms", expected: 123 * time.Millisecond, err: nil},
		{input: "456us", expected: 456 * time.Microsecond, err: nil},
		{input: "789ns", expected: 789 * time.Nanosecond, err: nil},
		{input: "1us", expected: 1 * time.Microsecond, err: nil},
		{input: "1ms", expected: 1 * time.Millisecond, err: nil},
		{input: "-1s", expected: -1 * time.Second, err: nil},
		{input: "", expected: 0, err: errors.New("time: invalid duration \"\"")},
		{input: "abc", expected: 0, err: errors.New("time: invalid duration \"abc\"")},
		{input: "1.5h", expected: 1*time.Hour + 30*time.Minute, err: nil},
		{input: "1h30m", expected: 1*time.Hour + 30*time.Minute, err: nil},
		{input: "1w2d3h4m5s", expected: 219*time.Hour + 4*time.Minute + 5*time.Second, err: nil},
		{input: "-1s", expected: -time.Second, err: nil},
	}

	for _, test := range tests {
		result, err := ParseDuration(test.input)
		if result != test.expected || (err != nil && test.err == nil) || (err != nil && test.err != nil && err.Error() != test.err.Error()) {
			t.Errorf("ParseDuration(%s) = %v, %v, expected %v, %v", test.input, result, err, test.expected, test.err)
		}
	}
}

func TestTimeDurationMarshalJSON(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{duration: 0, expected: `"0s"`},
		{duration: 1 * time.Second, expected: `"1s"`},
		{duration: 1 * time.Minute, expected: `"1m"`},
		{duration: 1 * time.Hour, expected: `"1h"`},
		{duration: 24 * time.Hour, expected: `"1d"`},
		{duration: 7 * 24 * time.Hour, expected: `"1w"`},
		{duration: 52 * 7 * 24 * time.Hour, expected: `"1y"`},
		{duration: 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, expected: `"1w3d23h47m16s854ms775us807ns"`},
		{duration: 250*52*7*24*time.Hour + 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond, expected: `"250y1w3d23h47m16s854ms775us807ns"`},
		{duration: 123 * time.Millisecond, expected: `"123ms"`},
		{duration: 456 * time.Microsecond, expected: `"456us"`},
		{duration: 789 * time.Nanosecond, expected: `"789ns"`},
		{duration: 1 * time.Microsecond, expected: `"1us"`},
		{duration: 1 * time.Millisecond, expected: `"1ms"`},
		{duration: -1 * time.Second, expected: `"-1s"`},
	}

	for _, test := range tests {
		result, err := TimeDuration(test.duration).MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON(%v) returned an error: %v", test.duration, err)
		}
		if string(result) != test.expected {
			t.Errorf("MarshalJSON(%v) = %s, expected %s", test.duration, string(result), test.expected)
		}
	}
}

func TestTimeDurationUnmarshalJSON(t *testing.T) {
	tests := []struct {
		input    string
		expected TimeDuration
		err      error
	}{
		{input: `"0s"`, expected: TimeDuration(0), err: nil},
		{input: `"1s"`, expected: TimeDuration(time.Second), err: nil},
		{input: `"1m"`, expected: TimeDuration(time.Minute), err: nil},
		{input: `"1h"`, expected: TimeDuration(time.Hour), err: nil},
		{input: `"1d"`, expected: TimeDuration(24 * time.Hour), err: nil},
		{input: `"1w"`, expected: TimeDuration(7 * 24 * time.Hour), err: nil},
		{input: `"1y"`, expected: TimeDuration(52 * 7 * 24 * time.Hour), err: nil},
		{input: `"1w3d23h47m16s854ms775us807ns"`, expected: TimeDuration(10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond), err: nil},
		{input: `"250y1w3d23h47m16s854ms775us807ns"`, expected: TimeDuration(250*52*7*24*time.Hour + 10*24*time.Hour + 23*time.Hour + 47*time.Minute + 16*time.Second + 854*time.Millisecond + 775*time.Microsecond + 807*time.Nanosecond), err: nil},
		{input: `"123ms"`, expected: TimeDuration(123 * time.Millisecond), err: nil},
		{input: `"456us"`, expected: TimeDuration(456 * time.Microsecond), err: nil},
		{input: `"789ns"`, expected: TimeDuration(789 * time.Nanosecond), err: nil},
		{input: `"1us"`, expected: TimeDuration(1 * time.Microsecond), err: nil},
		{input: `"1ms"`, expected: TimeDuration(1 * time.Millisecond), err: nil},
		{input: `"-1s"`, expected: TimeDuration(-1 * time.Second), err: nil},
		{input: `""`, expected: TimeDuration(0), err: errors.New("time: invalid duration \"\"")},
		{input: `"abc"`, expected: TimeDuration(0), err: errors.New("time: invalid duration \"abc\"")},
		{input: `"1.5h"`, expected: TimeDuration(1*time.Hour + 30*time.Minute), err: nil},
		{input: `"1h30m"`, expected: TimeDuration(1*time.Hour + 30*time.Minute), err: nil},
		{input: `"1w2d3h4m5s"`, expected: TimeDuration(219*time.Hour + 4*time.Minute + 5*time.Second), err: nil},
		{input: `"-1s"`, expected: TimeDuration(-time.Second), err: nil},
	}

	for _, test := range tests {
		var td TimeDuration
		err := td.UnmarshalJSON([]byte(test.input))
		if err != nil {
			if test.err == nil || err.Error() != test.err.Error() {
				t.Errorf("UnmarshalJSON(%s) returned an unexpected error: %v", test.input, err)
			}
		} else {
			if td != test.expected {
				t.Errorf("UnmarshalJSON(%s) = %v, expected %v", test.input, td, test.expected)
			}
		}
	}
}
