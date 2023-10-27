# GenGPGMail

A simple script to generate a GPG encrypted/signed email.


## Documentation

~~~~
Generate an encrypted email using GPG.                                        
                                                                              
Options:                                                                      
  -h, --help            show this help message and exit                       
  -e GPGENV, --env=GPGENV                                                     
                        The path to the gnupg environment directory, where the
                        keys are stored.                                      
  -l, --list            List keys in the gnupg environment.
  -i IMPORT_KEY, --import=IMPORT_KEY
                        The public key file to import in the gnupg
                        environment.
  -d RECIPIENT, --dest=RECIPIENT, --email-to=RECIPIENT
                        The recipient to encrypt for, can use key identifier.
  -f FILES, --file=FILES
                        The file to add as an attachment. Can be provided
                        multiple times to add multiple files.
  -s SUBJECT, --subject=SUBJECT
                        The email subject.
  -m MESSAGE, --message=MESSAGE
                        The text message to send. If not provided or equals
                        --, read standard input.
  -t, --trust           Trust recipient key, regardless of actual trust level.
  -c SIGNER, --sign=SIGNER
                        The optional key ID used to sign the email.
  -p PASS_FILE, --password-file=PASS_FILE
                        Path to a file containing a single line corresponding
                        to the selected signature key passphrase. Take
                        precedence on --password.
  --password=SIGN_PASSWORD
                        The password of the signing key. USE FOR TESTS ONLY.
  --send                Send an email using the provided SMTP parameters.
  --config=CONFIG       Path to a config file. Mandatory if --send is used, as
                        it should contains the SMTP params.

~~~~

## Examples

Considering you have a trusted key for bob@example.com in ./gpgenv.

`./gen_gpg_mail.py -m 'This is an encrypted message to bob@example.com.' -d bob@example.com`

Now, you have a private key for alice@example.com in ./gpgenv, and the related password in password.txt.

`./gen_gpg_mail.py -m 'This is an encrypted message to bob@example.com.' -d bob@example.com -c alice@example.com -p password.txt`

If you don't have trust in Bob's key, just add -t to the command line.

## Configuration file example

```json
{
  "recipient": "Recipient GPG Public Key",
  "signer": "Signing Key ID",
  "sign_password": "Signing Key Password",
  "smtp_server": "your.smtp.server.domain",
  "smtp_port": 587,
  "smtp_starttls": true,
  "smtp_user": "SMTP User",
  "smtp_password": "SMTP Password",
  "smtp_from": "From: mail header",
  "smtp_to": "To: mail header"
}
```