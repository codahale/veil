complete -c veil -n "__fish_use_subcommand" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_use_subcommand" -s V -l version -d 'Prints version information'
complete -c veil -n "__fish_use_subcommand" -f -a "secret-key" -d 'Generate a new secret key.'
complete -c veil -n "__fish_use_subcommand" -f -a "public-key" -d 'Derive a public key from a secret key.'
complete -c veil -n "__fish_use_subcommand" -f -a "derive-key" -d 'Derive a public key from another public key.'
complete -c veil -n "__fish_use_subcommand" -f -a "encrypt" -d 'Encrypt a message for a set of recipients.'
complete -c veil -n "__fish_use_subcommand" -f -a "decrypt" -d 'Decrypt and verify a message.'
complete -c veil -n "__fish_use_subcommand" -f -a "sign" -d 'Sign a message.'
complete -c veil -n "__fish_use_subcommand" -f -a "verify" -d 'Verify a signature.'
complete -c veil -n "__fish_use_subcommand" -f -a "help" -d 'Prints this message or the help of the given subcommand(s)'
complete -c veil -n "__fish_seen_subcommand_from secret-key" -d 'The output path for the encrypted secret key' -r -F
complete -c veil -n "__fish_seen_subcommand_from secret-key" -l time -d 'The time parameter for encryption' -r
complete -c veil -n "__fish_seen_subcommand_from secret-key" -l space -d 'The space parameter for encryption' -r
complete -c veil -n "__fish_seen_subcommand_from secret-key" -l passphrase-file -d 'The path to read the passphrase from' -r -F
complete -c veil -n "__fish_seen_subcommand_from secret-key" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from public-key" -d 'The path of the encrypted secret key' -r -F
complete -c veil -n "__fish_seen_subcommand_from public-key" -d 'The ID of the generated public key' -r
complete -c veil -n "__fish_seen_subcommand_from public-key" -l passphrase-file -d 'The path to read the passphrase from' -r -F
complete -c veil -n "__fish_seen_subcommand_from public-key" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from derive-key" -d 'The public key' -r
complete -c veil -n "__fish_seen_subcommand_from derive-key" -d 'The sub ID of the generated public key' -r
complete -c veil -n "__fish_seen_subcommand_from derive-key" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from encrypt" -d 'The path of the encrypted secret key' -r -F
complete -c veil -n "__fish_seen_subcommand_from encrypt" -d 'The ID of the public key to use' -r
complete -c veil -n "__fish_seen_subcommand_from encrypt" -d 'The path to the input file or \'-\' for stdin' -r -F
complete -c veil -n "__fish_seen_subcommand_from encrypt" -d 'The path to the output file or \'-\' for stdout' -r -F
complete -c veil -n "__fish_seen_subcommand_from encrypt" -d 'The recipient\'s public key' -r
complete -c veil -n "__fish_seen_subcommand_from encrypt" -l fakes -d 'Add fake recipients' -r
complete -c veil -n "__fish_seen_subcommand_from encrypt" -l padding -d 'Add random bytes of padding' -r
complete -c veil -n "__fish_seen_subcommand_from encrypt" -l passphrase-file -d 'The path to read the passphrase from' -r -F
complete -c veil -n "__fish_seen_subcommand_from encrypt" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from decrypt" -d 'The path of the encrypted secret key' -r -F
complete -c veil -n "__fish_seen_subcommand_from decrypt" -d 'The ID of the public key' -r
complete -c veil -n "__fish_seen_subcommand_from decrypt" -d 'The path to the input file or \'-\' for stdin' -r -F
complete -c veil -n "__fish_seen_subcommand_from decrypt" -d 'The path to the output file or \'-\' for stdout' -r -F
complete -c veil -n "__fish_seen_subcommand_from decrypt" -d 'The sender\'s public key' -r
complete -c veil -n "__fish_seen_subcommand_from decrypt" -l passphrase-file -d 'The path to read the passphrase from' -r -F
complete -c veil -n "__fish_seen_subcommand_from decrypt" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from sign" -d 'The path of the encrypted secret key' -r -F
complete -c veil -n "__fish_seen_subcommand_from sign" -d 'The ID of the public key to use' -r
complete -c veil -n "__fish_seen_subcommand_from sign" -d 'The path to the message file or \'-\' for stdin' -r -F
complete -c veil -n "__fish_seen_subcommand_from sign" -l passphrase-file -d 'The path to read the passphrase from' -r -F
complete -c veil -n "__fish_seen_subcommand_from sign" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from verify" -d 'The signer\'s public key' -r
complete -c veil -n "__fish_seen_subcommand_from verify" -d 'The path to the message file or \'-\' for stdin' -r -F
complete -c veil -n "__fish_seen_subcommand_from verify" -d 'The signature of the message' -r
complete -c veil -n "__fish_seen_subcommand_from verify" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from help" -s h -l help -d 'Prints help information'
complete -c veil -n "__fish_seen_subcommand_from help" -s V -l version -d 'Prints version information'
