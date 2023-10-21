#!/usr/bin/env python3
# -*-coding:UTF-8 -*

"""
Simple script to generate a GPG encrypted mail with attachment.
It's dirty and assume that almost everything goes fine, but do the job.

To use the script, you need to install the Python GPG library, either by pip or system-wide.
On Debian, python3-gnupg.
With pip, python-gnupg (use with version 0.4.3).
"""
import json
import mimetypes
import sys
from email import encoders, policy
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from itertools import chain
from optparse import OptionParser, Values
from pathlib import Path
from smtplib import SMTP

import gnupg

_DEFAULT_PARAMS = {
    'recipient': None,
    'message': '--',
    'subject': 'No subject',
    'attachments': list(),
    'trust': False,
    'gpgenv': './gpgenv',
    'signer': None,
    'sign_password': None
}


def _build_mail_to_encrypt(message: str, files: list) -> MIMEMultipart:
    """
    Create the MIMEMultipart mail containing the text message and the potentials attachments.

    :param message: The text message of the encrypted email.
    :param files: The files to attach and encrypt.
    :return: A MIMEMultipart mail object.
    """
    mail_to_encrypt = MIMEMultipart()
    mail_to_encrypt.policy = policy.SMTPUTF8
    if message == '--':
        message = sys.stdin.read()

    message_mail = MIMEBase('text', 'plain', charset='UTF-8')
    message_mail.policy = policy.SMTPUTF8
    message_mail.set_payload(message.encode('UTF-8'))
    encoders.encode_quopri(message_mail)
    mail_to_encrypt.attach(message_mail)

    if files:
        for file in files:
            path = Path(file)

            guessed_type = mimetypes.guess_type(path.absolute().as_uri())[0]

            if not guessed_type:
                print('Could not guess file %s mime-type, using application/octet-stream.' % file, file=sys.stderr)
                guessed_type = 'application/octet-stream'

            mimetype = guessed_type.split('/')

            mail_attachment = MIMEBase(mimetype[0], mimetype[1])
            mail_attachment.policy = policy.SMTPUTF8
            mail_attachment.set_payload(open(str(path.absolute()), 'rb').read())
            encoders.encode_base64(mail_attachment)
            mail_attachment.add_header('Content-Disposition', "attachment", filename=path.name)

            mail_to_encrypt.attach(mail_attachment)

    return mail_to_encrypt


def encrypt_mail(**in_params) -> MIMEMultipart:
    """
    Build and encrypt an email using the given parameters.

    :param recipient: Recipient the mail will be encrypted for. Can use key fingerprint or id.
    :param subject: The email subject.
    :param message: The email message. If "--" is used, read the standard input.
    :param attachments: A list of str containing the names of mail attachments.
    :param gpgenv: The path to the GPG environment.
    :param trust: Whether to always trust or not the recipient key.
    :param signer: The key ID used to sign the email.
    :param sign_password: The password of the signing key.
    :return: The MIMEMultipart corresponding to the encrypted email.
    """

    params = dict(chain(_DEFAULT_PARAMS.items(), in_params.items()))

    gpg = gnupg.GPG(gnupghome=params['gpgenv'])

    mail_to_encrypt = _build_mail_to_encrypt(params['message'], params['attachments'])

    if params['signer']:
        signature = gpg.sign(str(mail_to_encrypt),
                             keyid=params['signer'],
                             passphrase=params['sign_password'],
                             detach=True)

        # Values defined from gnupg/common/openpgpdefs.h and  gnupg/tests/openpgp/mds.scm
        hash_mapping = {'1': 'md5',
                        '2': 'sha1',
                        '3': 'ripemd160',
                        '8': 'sha256',
                        '9': 'sha384',
                        '10': 'sha512',
                        '11': 'sha224'
                        }

        signed_mail = MIMEMultipart('signed',
                                    micalg='pgp-%s' % hash_mapping[signature.hash_algo],
                                    protocol='application/pgp-signature')
        signed_mail.policy = policy.SMTPUTF8
        signed_mail.attach(mail_to_encrypt)

        signature_part = MIMEApplication(str(signature), 'pgp-signature', encoders.encode_noop, name='signature.asc')
        signature_part.policy = policy.SMTPUTF8

        signed_mail.attach(signature_part)
        mail_to_encrypt = signed_mail

    encrypted_mail = gpg.encrypt(str(mail_to_encrypt), params['recipient'], always_trust=params['trust'])

    if not encrypted_mail.ok:
        print(encrypted_mail.status, file=sys.stderr)
        sys.exit(2)

    mail_to_send = MIMEMultipart('encrypted', protocol='application/pgp-encrypted')
    mail_to_send.policy = policy.SMTPUTF8
    mail_to_send.add_header('Subject', params['subject'])

    version_part = MIMEApplication("Version: 1", 'pgp-encrypted', encoders.encode_7or8bit)
    version_part.policy = policy.SMTPUTF8
    mail_to_send.attach(version_part)

    content_part = MIMEApplication(str(encrypted_mail),
                                   'octet-stream',
                                   encoders.encode_7or8bit,
                                   name='encrypted.asc')
    content_part.policy = policy.SMTPUTF8
    mail_to_send.attach(content_part)

    return mail_to_send


def _encrypt_mail(options: Values) -> str:
    """
    Wrapper for the multiple arguments of "encrypt_mail" function.
    Return its result as a string.

    Select the right method to get the signing key's password (file or argument).

    :param options:
    :return:
    """

    sign_password = None

    if options.pass_file:
        path = Path(options.pass_file)

        if path.is_file():
            sign_password = open(options.pass_file, 'r').readline().rstrip('\n')
        else:
            print("Can't read the '%s' file." % options.pass_file, file=sys.stderr)
            sys.exit(3)
    elif options.sign_password:
        sign_password = options.sign_password

    if options.config:
        file_config = json.load(open(options.config))
    else:
        file_config = dict()

    cli_config = {k: v for k, v in dict(recipient=options.recipient,
                                        subject=options.subject,
                                        message=options.message,
                                        attachments=options.files,
                                        gpgenv=options.gpgenv,
                                        trust=options.trust,
                                        signer=options.signer,
                                        sign_password=sign_password).items() if v is not None}

    config = dict(chain(file_config.items(), cli_config.items()))

    return str(encrypt_mail(**config))


def _send_mail(mail: str, options: Values):
    if options.config:
        file_config = json.load(open(options.config))
    else:
        print("When sending, config file is mandatory.")

    with SMTP(file_config["smtp_server"], port=file_config["smtp_port"]) as smtp:
        if file_config["smtp_starttls"]:
            print(smtp.starttls())
        if file_config["smtp_user"]:
            print(smtp.login(file_config["smtp_user"], file_config["smtp_password"]))
        print(smtp.sendmail(file_config["smtp_from"], file_config["smtp_to"], mail))


def _import_key(options: Values) -> None:
    """
    Import/update a key in the GPG environment. Then the key can be used to encrypt emails.

    The result of the import is printed on the standard output.

    :param options:
    :return:
    """
    gpg = gnupg.GPG(gnupghome=options.gpgenv)

    key_data = open(options.import_key).read()

    for result in gpg.import_keys(key_data).results:
        print('OK : %s' % result['ok'])
        print('Fingerprint : %s' % result['fingerprint'])
        print('Text : %s' % result['text'])


def _list_keys(options: Values) -> None:
    """
    List all keys currently available in the GnuPG environment defined by the options.gpgenv parameter.

    :param options: A Values containing the options.gpgenv attribute.
    :return: None
    """
    gpg = gnupg.GPG(gnupghome=options.gpgenv)
    for key in gpg.list_keys():
        print(key['uids'])
        for key_data, key_value in key.items():
            if key_value:
                print('\t%s : %s' % (key_data, key_value))


def main():
    """
    Main method. Define the usable arguments of the script and select the right action to launch.
    The order of precedence is -l, -i, then -d.

    :return:
    """
    parser = OptionParser(description="Generate an encrypted email using GPG.")

    parser.add_option('-e', '--env',
                      dest='gpgenv',
                      help='The path to the gnupg environment directory, where the keys are stored.')
    parser.add_option('-l', '--list',
                      dest='list',
                      action="store_true",
                      help='List keys in the gnupg environment.')
    parser.add_option('-i', '--import',
                      dest='import_key',
                      help='The public key file to import in the gnupg environment.')
    parser.add_option('-d', '--dest', '--email-to',
                      dest='recipient',
                      help='The recipient to encrypt for, can use key identifier.')

    parser.add_option('-f', '--file',
                      dest='files',
                      action="append",
                      help='The file to add as an attachment. Can be provided multiple times to add multiple files.')
    parser.add_option('-s', '--subject',
                      dest='subject',
                      help='The email subject.')
    parser.add_option('-m', '--message',
                      dest='message',
                      help='The text message to send. If not provided or equals --, read standard input.')
    parser.add_option('-t', '--trust',
                      dest='trust',
                      action='store_true',
                      help='Trust recipient key, regardless of actual trust level.')
    parser.add_option('-c', '--sign',
                      dest='signer',
                      help='The optional key ID used to sign the email.')
    parser.add_option('-p', '--password-file',
                      dest='pass_file',
                      help='Path to a file containing a single line corresponding to '
                           'the selected signature key passphrase. Take precedence on --password.')
    parser.add_option('--password',
                      dest='sign_password',
                      help='The password of the signing key. USE FOR TESTS ONLY.'
                      )
    parser.add_option("--send",
                      dest="send",
                      action='store_true',
                      help="Send an email using the provided SMTP parameters."
                      )
    parser.add_option('--config',
                      dest='config',
                      help='Path to a config file. Mandatory if --send is used, as it should contains the SMTP params.')

    (options, args) = parser.parse_args()

    if options.list:
        _list_keys(options)
    elif options.import_key:
        _import_key(options)
    elif options.recipient or options.config:
        if options.send:
            mail = _encrypt_mail(options)
            _send_mail(mail, options)
        else:
            print(_encrypt_mail(options))
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

    sys.exit(0)
