# Just Another Mail Server (JAMS)

JAMS is a FOSS alternative to [Proton Mail](mail.proton.me)! 

The mail server will be client-less, allowing users to choose their own local mail clients (whether it be ThunderBird, Outlook, GMail, etc.) without the risk of bloating their systems with unnecessary extra software. 

JAMS, in it's current form, is an experimental project with the following plans:

### Current  Mail Server Plans:
- Email Tx/Rx + Client Access: IMAP4, SMTP server 🟢, 
- Zero Access storage 🔴, 
- Email filtering 🔴, 
- DKIM/SPF/DMARC 🟢, 
- PGP/GPG signing 🔴, 
- Multi-User Accounts 🟢,
- Email Aliasing: configurable aliases 🟠:
- - Self-Terminating Addresses, 
- - Only receive from emails from domains you want
- - Automatic Email dropping (Timer based, preferable if you want to receive a confirmation link but no spam!)
- TLS: STARTLS, LetsEncrypt, etc. 🟢,
- And the normal you can expect from an email server 🟠

The above list will be marked with the following symbols to indicate status:
- 🟢 -> Complete
- 🔴 -> Not Started
- 🟠 -> In Progress
- ⚠️ -> Known Security Risk - Awaiting Patch

If there's any bugs please open a ticket, or if there's any security issues, contact us at: tr4ceang3l@proton.me (ironic, right?) providing a detailed report regarding the vulnerability and we'll review and triage accordingly, within 28 days of submission.
