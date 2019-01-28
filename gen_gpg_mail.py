#!/usr/bin/env python3
# -*-coding:UTF-8 -*

"""
Simple script to generate a GPG encrypted mail with attachment.
It's dirty and assume that almost everything goes fine, but do the job.

To use the script, you need to install the Python GPG library, either by pip or system-wide.
On Debian, python3-gnupg.
With pip, python-gnupg (use with version 0.4.3).
"""

import mimetypes
import sys
from email import encoders
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from optparse import OptionParser, Values
from pathlib import Path

import gnupg

_MAIL_DEFAULT_MESSAGE = '--'
_MAIL_DEFAULT_SUBJECT = 'No subject'
_MAIL_DEFAULT_ATTACHMENTS = list()

_DEFAULT_GPG_ENV = './gpgenv'
_DEFAULT_GPG_TRUST = False


def _build_mail_to_encrypt(message: str, files: list) -> MIMEMultipart:
    """
    Create the MIMEMultipart mail containing the text message and the potentials attachments.

    :param message: The text message of the encrypted email.
    :param files: The files to attach and encrypt.
    :return: A MIMEMultipart mail object.
    """
    mail_to_encrypt = MIMEMultipart()
    if message == '--':
        mail_to_encrypt.attach(MIMEText(sys.stdin.read()))
    else:
        mail_to_encrypt.attach(MIMEText(message))

    if files:
        for file in files:
            path = Path(file)

            guessed_type = mimetypes.guess_type(path.absolute().as_uri())[0]

            if not guessed_type:
                print('Could not guess file %s mime-type, using application/octet-stream.' % file, file=sys.stderr)
                guessed_type = 'application/octet-stream'

            mimetype = guessed_type.split('/')

            mail_attachment = MIMEBase(mimetype[0], mimetype[1])
            mail_attachment.set_payload(open(str(path.absolute()), 'rb').read())
            encoders.encode_base64(mail_attachment)
            mail_attachment.add_header('Content-Disposition', "attachment; filename= %s" % path.name)

            mail_to_encrypt.attach(mail_attachment)

    return mail_to_encrypt


def encrypt_mail(recipient: str, subject=_MAIL_DEFAULT_SUBJECT, message=_MAIL_DEFAULT_MESSAGE,
                 files=_MAIL_DEFAULT_ATTACHMENTS, gpgenv=_DEFAULT_GPG_ENV, trust=_DEFAULT_GPG_TRUST) -> MIMEMultipart:
    """
    Build and encrypt an email using the given parameters.

    :param recipient: Recipient the mail will be encrypted for. Can use key fingerprint or id.
    :param subject: The email subject.
    :param message: The email message. If "--" is used, read the standard input.
    :param files: A list of str containing the names of mail attachments.
    :param gpgenv: The path to the GPG environment.
    :param trust: Whether to always trust or not the recipient key.
    :return: The MIMEMultipart corresponding to the encrypted email.
    """
    gpg = gnupg.GPG(gnupghome=gpgenv)

    mail_to_encrypt = _build_mail_to_encrypt(message, files)

    encrypted_mail = gpg.encrypt(str(mail_to_encrypt), recipient, always_trust=trust)

    if not encrypted_mail.ok:
        print(encrypted_mail.status, file=sys.stderr)
        sys.exit(2)

    mail_to_send = MIMEMultipart('encrypted', protocol='application/pgp-encrypted')
    mail_to_send.attach(MIMEApplication("Version: 1", 'pgp-encrypted', encoders.encode_7or8bit))
    mail_to_send.attach(MIMEApplication(str(encrypted_mail),
                                        'octet-stream',
                                        encoders.encode_7or8bit,
                                        name='encrypted.asc'))
    mail_to_send.add_header('Subject', subject)

    return mail_to_send


def _encrypt_mail(options: Values) -> None:
    """
    Wrapper for the multiple arguments "encrypt_mail" function. Print it's result in the standard output.

    :param options:
    :return:
    """
    print(str(encrypt_mail(options.recipient,
                           options.subject,
                           options.message,
                           options.files,
                           options.gpgenv,
                           options.trust)))


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
        print(result)


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
                      default=_DEFAULT_GPG_ENV,
                      help='The path to the gnupg environment directory, where the keys are stored. (%default)')
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

    parser.add_option('-f', '--send', '--file',
                      dest='files',
                      action="append",
                      help='The file to add as an attachment. Can be provided multiple times to add multiple files.')
    parser.add_option('-s', '--subject',
                      dest='subject',
                      default=_MAIL_DEFAULT_SUBJECT,
                      help='The email subject. (%default)')
    parser.add_option('-m', '--message',
                      dest='message',
                      default=_MAIL_DEFAULT_MESSAGE,
                      help='The text message to send. If not provided or equals --, read standard input. (%default)')
    parser.add_option('-t', '--trust',
                      dest='trust',
                      action='store_true',
                      help='Trust recipient key, regardless of actual trust level.')

    (options, args) = parser.parse_args()

    if options.list:
        _list_keys(options)
    elif options.import_key:
        _import_key(options)
    elif options.recipient:
        _encrypt_mail(options)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

    sys.exit(0)
