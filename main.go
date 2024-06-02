package main

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/janstuemmel/fck-gauth/authenticator"
	"github.com/mdp/qrterminal/v3"
)

func getExportData(str string) (*authenticator.AuthenticatorExport, error) {
	b64 := strings.Replace(str, "otpauth-migration://offline?data=", "", 1)
	exportString, err := base64.StdEncoding.DecodeString(b64)

	if err != nil {
		return nil, err
	}

	exportData := &authenticator.AuthenticatorExport{}

	err = proto.Unmarshal(exportString, exportData)

	return exportData, err
}

func readInput() string {
	var input string

	if len(os.Args) < 2 {
		stdin := os.Stdin
		r := bufio.NewReader(stdin)
		l, _, _ := r.ReadLine()
		input = string(l)
	} else {
		input = os.Args[1]
	}

	return input
}

func main() {

	export, err := getExportData(readInput())

	if err != nil {
		panic(err)
	}

	for _, otp := range export.Otp {
		secret := base32.StdEncoding.EncodeToString(otp.Secret)
		uri := fmt.Sprintf("otpauth://totp/%s?secret=%s\n&issuer=%s", otp.Name, secret, otp.Issuer)
		fmt.Println()
		fmt.Println("Name:\t", otp.Name)
		fmt.Println("Issuer:\t", otp.Issuer)
		fmt.Println("Secret:\t", secret)
		qrterminal.Generate(uri, qrterminal.L, os.Stdout)
		fmt.Println()
	}

}
