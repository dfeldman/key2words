package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	privateKeyHeader = "PRIVATE KEY"
	outputFile       = "restored_key"
)

var (
	colorReset  = "\033[0m\n"
	colorRed    = "\033[31m\n"
	colorGreen  = "\033[32m\n"
	colorYellow = "\033[33m\n"
)

func Red(format string, a ...interface{}) {
	if isOutputToConsole() {
		fmt.Printf(colorRed+format+colorReset, a...)
	} else {
		fmt.Printf(format, a...)
	}
}

func Green(format string, a ...interface{}) {
	if isOutputToConsole() {
		fmt.Printf(colorGreen+format+colorReset, a...)
	} else {
		fmt.Printf(format, a...)
	}
}

func Yellow(format string, a ...interface{}) {
	if isOutputToConsole() {
		fmt.Printf(colorYellow+format+colorReset, a...)
	} else {
		fmt.Printf(format, a...)
	}
}

func isOutputToConsole() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))

}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "backup":
		if len(os.Args) != 3 {
			printUsage()
			os.Exit(1)
		}
		privateKeyFile := os.Args[2]
		mnemonic, err := backupKey(privateKeyFile, nil)
		if err != nil {
			Red("❌ Error: %s", err)
			os.Exit(1)
		}
		Green("✅ Private key successfully backed up!")
		Yellow("🔑 Mnemonic:")
		fmt.Println(mnemonic)
	case "restore":
		if len(os.Args) != 3 {
			printUsage()
			os.Exit(1)
		}
		mnemonic := os.Args[2]
		privateKeyBytes, authorizedKeyBytes, err := restoreKey(mnemonic)
		if err != nil {
			Red("❌ Error: %s", err)
			os.Exit(1)
		}

		err = os.WriteFile(outputFile, privateKeyBytes, 0600)
		if err != nil {
			Red("❌ Error: %s", err)
			os.Exit(1)
		}

		err = os.WriteFile(outputFile+".pub", authorizedKeyBytes, 0644)
		if err != nil {
			Red("❌ Error: %s", err)
			os.Exit(1)
		}

		Green("✅ Private key successfully restored!")
		Yellow("🔑 Private key saved to: %s", outputFile)
		Yellow("🔑 Public key saved to: %s.pub", outputFile)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  key2words backup <private_key_file>")
	fmt.Println("  key2words restore <mnemonic>")
}

func isPasswordError(err error) bool {
	var kerr *ssh.PassphraseMissingError
	return errors.As(err, &kerr)
}

func askKeyPassphrase(path string) ([]byte, error) {
	defer fmt.Fprintf(os.Stderr, "\n")
	return readPassword(fmt.Sprintf("Enter the passphrase to unlock %q: ", path))
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return password, nil
}

func parsePrivateKey(bts, pass []byte) (interface{}, error) {
	if len(pass) == 0 {
		//nolint: wrapcheck
		return ssh.ParseRawPrivateKey(bts)
	}
	//nolint: wrapcheck
	return ssh.ParseRawPrivateKeyWithPassphrase(bts, pass)
}

func backupKey(privateKeyFile string, pass []byte) (string, error) {
	mnemonic := ""
	privateKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	privateKey, err := parsePrivateKey(privateKeyBytes, pass)
	if err != nil && isPasswordError(err) {
		pass, err := askKeyPassphrase(privateKeyFile)
		if err != nil {
			return "", err
		}
		return backupKey(privateKeyFile, pass)
	}
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	switch key := privateKey.(type) {
	case *ed25519.PrivateKey:
		mnemonic, err = toMnemonic(privateKey.(*ed25519.PrivateKey).Seed())
		if err != nil {
			return "", err
		}

	default:
		return "", fmt.Errorf("unknown key type: %v", key)
	}

	return mnemonic, nil
}

func restoreKey(mnemonic string) ([]byte, []byte, error) {
	privateKey, err := fromMnemonic(mnemonic)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create public key: %w", err)
	}

	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  privateKeyHeader,
		Bytes: privateKey,
	})

	authorizedKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	return privateKeyBytes, authorizedKeyBytes, err
}

func toMnemonic(seed []byte) (string, error) {
	words, err := NewMnemonic(seed)
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}
	return words, nil
}

func fromMnemonic(mnemonic string) (ed25519.PrivateKey, error) {
	seed, err := EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to get seed from mnemonic: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
