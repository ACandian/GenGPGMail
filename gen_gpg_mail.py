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


def _build_mail_to_encrypt(options: Values) -> MIMEMultipart:
    """

    :param options:
    :return:
    """
    mail_to_encrypt = MIMEMultipart()
    mail_to_encrypt.attach(MIMEText(options.message))

    attachment_file = options.send_file
    path = Path(attachment_file)

    guessed_type = mimetypes.guess_type(path.absolute().as_uri())[0]

    if not guessed_type:
        print('Could not guess file mime-type, using application/octet-stream.', file=sys.stderr)
        guessed_type = 'application/octet-stream'

    mimetype = guessed_type.split('/')

    mail_attachment = MIMEBase(mimetype[0], mimetype[1])
    mail_attachment.set_payload(open(str(path.absolute()), 'rb').read())
    encoders.encode_base64(mail_attachment)
    mail_attachment.add_header('Content-Disposition', "attachment; filename= %s" % path.name)

    mail_to_encrypt.attach(mail_attachment)

    return mail_to_encrypt


def sendmail(options: Values) -> None:
    """

    :param options:
    :return:
    """
    gpg = gnupg.GPG(gnupghome=options.gpgenv)

    if not options.email_to:
        print('Recipient is mandatory.', file=sys.stderr)
        sys.exit(1)

    mail_to_encrypt = _build_mail_to_encrypt(options)

    encrypted_mail = gpg.encrypt(str(mail_to_encrypt), options.email_to, always_trust=options.trust)

    if not encrypted_mail.ok:
        print(encrypted_mail.status, file=sys.stderr)
        sys.exit(2)

    mail_to_send = MIMEMultipart('encrypted', protocol='application/pgp-encrypted')
    mail_to_send.attach(MIMEApplication("Version: 1", 'pgp-encrypted', encoders.encode_7or8bit))
    mail_to_send.attach(MIMEApplication(str(encrypted_mail),
                                        'octet-stream',
                                        encoders.encode_7or8bit,
                                        name='encrypted.asc'))
    mail_to_send.add_header('Subject', options.subject)

    print(str(mail_to_send))


def import_key(options: Values) -> None:
    """

    :param options:
    :return:
    """
    gpg = gnupg.GPG(gnupghome=options.gpgenv)

    key_data = open(options.import_key).read()

    for result in gpg.import_keys(key_data).results:
        print(result)


def list_keys(options: Values) -> None:
    """

    :param options:
    :return:
    """
    gpg = gnupg.GPG(gnupghome=options.gpgenv)
    for key in gpg.list_keys():
        print(key['uids'])
        for key_data, key_value in key.items():
            if key_value:
                print('\t%s : %s' % (key_data, key_value))


def main():
    """

    :return:
    """
    parser = OptionParser()

    parser.add_option('-e', '--env',
                      dest='gpgenv',
                      default='./gpgenv',
                      help='The path to the gnupg environment directory, where the keys are stored. (%default)')
    parser.add_option('-l', '--list',
                      dest='list',
                      action="store_true",
                      help='List keys in the gnupg environment.')
    parser.add_option('-i', '--import',
                      dest='import_key',
                      help='The public key file to import in the gnupg environment.')
    parser.add_option('-f', '--send', '--file',
                      dest='send_file',
                      help='The file to add as an attachment.')
    parser.add_option('-d', '--dest', '--email-to',
                      dest='email_to',
                      help='The recipient to encrypt for, can use key identifier.')
    parser.add_option('-s', '--subject',
                      dest='subject',
                      default='No subject',
                      help='The email subject. (%default)')
    parser.add_option('-m', '--message',
                      dest='message',
                      default='',
                      help='The text message. (%default)')
    parser.add_option('-t', '--trust',
                      dest='trust',
                      action='store_true',
                      help='Trust recipient key, regardless of actuel trust level.')

    (options, args) = parser.parse_args()

    if options.list:
        list_keys(options)
    elif options.import_key:
        import_key(options)
    elif options.send_file:
        sendmail(options)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

    sys.exit(0)
