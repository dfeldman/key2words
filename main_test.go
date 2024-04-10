package main

import (
	"strings"
	"testing"
)

func TestBackupRestoreKnownKey(t *testing.T) {
	const expectedMnemonic = `
		alter gap broom kitten orient over settle work honey rule
		coach system wage effort mask void solid devote divert
		quarter quote broccoli jaguar lady
	`
	const expectedPrivateKey = `-----BEGIN PRIVATE KEY-----
B2vocz2pyTvxH+xtN6Sy7m9ijWIfrM6nmP9XuwA43cvJQSoksziSwoefzN4O7jzR
v6vJpyOW9CnGXgkUjVajHA==
-----END PRIVATE KEY-----
`
	const expectedAuthorizedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlBKiSzOJLCh5/M3g7uPNG/q8mnI5b0KcZeCRSNVqMc\n"
	t.Run("backup", func(t *testing.T) {
		mnemonic, err := backupKey("testkey1.works.ed25519", nil)
		if err != nil {
			t.Error(err)
		}
		if mnemonic != strings.Join(strings.Fields(expectedMnemonic), " ") {
			t.Errorf("Expected mnemonic: %s, got: %s", expectedMnemonic, mnemonic)
		}
	})

	t.Run("backup file that does not exist", func(t *testing.T) {
		_, err := backupKey("nope", nil)
		if err == nil {
			t.Log("Expected error, got nil")
		}
	})

	t.Run("backup invalid ssh key", func(t *testing.T) {
		_, err := backupKey("main.go", nil)
		if err == nil {
			t.Log("Expected error, got nil")
		}
	})

	t.Run("backup key of another type", func(t *testing.T) {
		_, err := backupKey("testdata/id_rsa", nil)
		if err == nil {
			t.Log("Expected error, got nil")
		}
	})

	t.Run("backup key with password", func(t *testing.T) {
		const expectedMnemonic = `assume knee laundry logic soft fit quantum
			puppy vault snow author alien famous comfort neglect habit
			emerge fabric trophy wine hold inquiry clown govern`

		mnemonic, err := backupKey("testkey2.password.ed25519", []byte("asd"))
		if err != nil {
			t.Error(err)
		}
		if mnemonic != strings.Join(strings.Fields(expectedMnemonic), " ") {
			t.Errorf("Expected mnemonic: %s, got: %s", expectedMnemonic, mnemonic)
		}
	})

	t.Run("restore", func(t *testing.T) {
		privateKeyBytes, authorizedKeyBytes, err := restoreKey(expectedMnemonic)
		if err != nil {
			t.Error(err)
		}
		if string(privateKeyBytes) != expectedPrivateKey {
			t.Errorf("Expected nil, got: %v", string(privateKeyBytes))
		}
		if string(authorizedKeyBytes) != expectedAuthorizedKey {
			t.Errorf("Expected nil, got: XXX%vXXX", string(authorizedKeyBytes))
		}
	})
}
