# NvPass -- Neovim secure vault

This plugin provides a secure vault for neovim.

# Installation

You must first build and install the vault program:
```
cargo build --release
mv target/release/nvpass <INSTALL DIR>
```

Then setup the plugin:
```
{
    "ef3d0c3e/nvpass",
    opts = {
        vault_bin = vim.fn.expand("~/path/to/nvpass")
    }
},
```

# Usage

This plugin will work on any file with the `.nvpass` extension.
When you open a file, the plugin will prompt you for a password to decrypt the file.

Once decrypted, you will see the content of the file in a virtual buffer, saving this buffer will re-encrypt and save the vault file.
Note that in order to prevent accidental data losses, the vault file (encrypted) is first written to a temporary directory, before overwriting the original file on disk.

# Security

Because of how neovim works, it's not really possible to make a secure password manager.
For instance, you might have plugins that send the decrypted plaintext to other programs for lints, syntax, spell checking, etc.
This plugin tries it's best to mitigate these by disabling some options inside neovim (backups, swapfiles, undofiles, ...) and tries to keep as little information in memory as necessary.

However keep in mind that passphrase is stored in memory for as long as a nvpass buffer is open.
To further mitigate risks, I advise you to close neovim when you're done accessing a nvpass file.
Secrets communicated to the vault executable are sent through a pipe, to prevent being exposed via strace, shell environment, system logs and debuggers.

Therefore, I strongly advise against using this plugin for any sensitive data, however, I try to make sure the vault executable properly secures secrets.
The current version uses chacha20-poly1305 for encryption/authentication, with argon2 for key derivation (32-byte random salt).

# License

This project is licensed under the GNU GPL version 3 or later.
See [LICENSE](./LICENSE) for more information.
