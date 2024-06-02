package main

import (
	"strings"
	"testing"
)

var TEST = "otpauth-migration://offline?data=ChwKCrhlbGxvId6tvu8SA2ZvbxoDYmFyIAEoATACChwKCrhlbGyvId6tvu8SA2JhehoDYmxhIAEoATACEAEYASAAKIa94NIC"
var TEST_B64 = "ChwKCrhlbGxvId6tvu8SA2ZvbxoDYmFyIAEoATACChwKCrhlbGyvId6tvu8SA2JhehoDYmxhIAEoATACEAEYASAAKIa94NIC"

func TestGetExportData(t *testing.T) {
	t.Run("should unmarshal migration uri correcly", func(t *testing.T) {
		data, err := getExportData(TEST)
		assert(t, nil, err)
		assert(t, "foo", data.Otp[0].Name)
		assert(t, "bar", data.Otp[0].Issuer)
	})

	t.Run("should unmarshal migration base64 correcly", func(t *testing.T) {
		data, err := getExportData(TEST_B64)
		assert(t, nil, err)
		assert(t, "foo", data.Otp[0].Name)
		assert(t, "bar", data.Otp[0].Issuer)
	})

	t.Run("should error when for invalid protobuf", func(t *testing.T) {
		_, err := getExportData("Zm9v")
		assert(t, true, strings.Contains(err.Error(), "cannot parse invalid wire-format data"))
	})

	t.Run("should error for invalid base64", func(t *testing.T) {
		_, err := getExportData("@!$$")
		assert(t, "illegal base64 data at input byte 0", err.Error())
	})
}

func assert(t *testing.T, want interface{}, have interface{}) {

	// mark as test helper function
	t.Helper()

	if want != have {
		t.Error("Assertion failed for", t.Name(), "\n\twanted:\t", want, "\n\thave:\t", have)
	}
}
