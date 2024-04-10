# key2words

key2words is a Go program that allows you to backup and restore SSH private keys using memorizable seed phrases. It utilizes the BIP39 algorithm to generate mnemonic phrases from the private key's seed, providing a secure and convenient way to backup and restore your SSH keys.

The project is based on [Melt](https://github.com/charmbracelet/melt). The only change is to remove as many external dependencies as possible, for maximum security. 

## Features

- Backup an SSH private key and generate a mnemonic phrase
- Restore an SSH private key from a mnemonic phrase
- User-friendly command-line interface with colorful output
- Error handling and informative messages
- Supports Ed25519 private keys

## Installation

1. Make sure you have Go installed on your system.
2. Clone this repository:
git clone https://github.com/dfeldman/key2words.git
3. Change to the project directory:
cd key2words
4. Build the program:
go build

## Usage

### Backup a private key

To backup an SSH private key and generate a mnemonic phrase, run the following command:
key2words backup <private_key_file>

Replace `<private_key_file>` with the path to your SSH private key file.

Example:
key2words backup ~/.ssh/id_ed25519

The program will output the generated mnemonic phrase.

### Restore a private key

To restore an SSH private key from a mnemonic phrase, run the following command:
key2words restore <mnemonic>

Replace `<mnemonic>` with the mnemonic phrase you obtained during the backup process.

Example:
key2words restore "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"

The program will restore the private key and save it to the `restored_key` file, along with the corresponding public key in `restored_key.pub`.

## Credits

key2words is based on the [Melt](https://github.com/charmbracelet/melt) project by Carlos Alexander Becker. Large parts of the code are borrowed from that project.

## License

This program is licensed under the [MIT License](LICENSE).