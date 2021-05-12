
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'veil' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'veil'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-')) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'veil' {
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('-V', 'V', [CompletionResultType]::ParameterName, 'Prints version information')
            [CompletionResult]::new('--version', 'version', [CompletionResultType]::ParameterName, 'Prints version information')
            [CompletionResult]::new('secret-key', 'secret-key', [CompletionResultType]::ParameterValue, 'Generate a new secret key.')
            [CompletionResult]::new('public-key', 'public-key', [CompletionResultType]::ParameterValue, 'Derive a public key from a secret key.')
            [CompletionResult]::new('derive-key', 'derive-key', [CompletionResultType]::ParameterValue, 'Derive a public key from another public key.')
            [CompletionResult]::new('encrypt', 'encrypt', [CompletionResultType]::ParameterValue, 'Encrypt a message for a set of recipients.')
            [CompletionResult]::new('decrypt', 'decrypt', [CompletionResultType]::ParameterValue, 'Decrypt and verify a message.')
            [CompletionResult]::new('sign', 'sign', [CompletionResultType]::ParameterValue, 'Sign a message.')
            [CompletionResult]::new('verify', 'verify', [CompletionResultType]::ParameterValue, 'Verify a signature.')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Prints this message or the help of the given subcommand(s)')
            break
        }
        'veil;secret-key' {
            [CompletionResult]::new('--time', 'time', [CompletionResultType]::ParameterName, 'The time parameter for encryption')
            [CompletionResult]::new('--space', 'space', [CompletionResultType]::ParameterName, 'The space parameter for encryption')
            [CompletionResult]::new('--passphrase-file', 'passphrase-file', [CompletionResultType]::ParameterName, 'The path to read the passphrase from')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;public-key' {
            [CompletionResult]::new('--passphrase-file', 'passphrase-file', [CompletionResultType]::ParameterName, 'The path to read the passphrase from')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;derive-key' {
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;encrypt' {
            [CompletionResult]::new('--fakes', 'fakes', [CompletionResultType]::ParameterName, 'Add fake recipients')
            [CompletionResult]::new('--padding', 'padding', [CompletionResultType]::ParameterName, 'Add random bytes of padding')
            [CompletionResult]::new('--passphrase-file', 'passphrase-file', [CompletionResultType]::ParameterName, 'The path to read the passphrase from')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;decrypt' {
            [CompletionResult]::new('--passphrase-file', 'passphrase-file', [CompletionResultType]::ParameterName, 'The path to read the passphrase from')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;sign' {
            [CompletionResult]::new('--passphrase-file', 'passphrase-file', [CompletionResultType]::ParameterName, 'The path to read the passphrase from')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;verify' {
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            break
        }
        'veil;help' {
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Prints help information')
            [CompletionResult]::new('-V', 'V', [CompletionResultType]::ParameterName, 'Prints version information')
            [CompletionResult]::new('--version', 'version', [CompletionResultType]::ParameterName, 'Prints version information')
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
