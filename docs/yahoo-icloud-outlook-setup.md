# Yahoo, iCloud and Outlook.com mailboxes (IMAP)

These providers have no OAuth we can use for a third-party app, so the client
creates an **app password** and we connect over IMAP with TLS. The password is
encrypted with the token KEK before it is stored (`core/crypto.py`); the
client can revoke it at any time from their provider.

Each client does this on their own device. Sit with them or do a screen share;
it takes five minutes.

## IMAP settings we use

| Provider | IMAP host | Port | Login | Notes |
|----------|-----------|------|-------|-------|
| Yahoo Mail | `imap.mail.yahoo.com` | 993 (SSL) | full address | app password required |
| iCloud Mail | `imap.mail.me.com` | 993 (SSL) | the Apple ID email (full address) | app-specific password required; 2FA must be on |
| Outlook.com / Hotmail / Live | `outlook.office365.com` | 993 (SSL) | full address | see Outlook note below |

The worker polls every `RS_IMAP_POLL_SECONDS` (30 s) using UIDNEXT as the
cursor, so nothing is missed between polls.

## Yahoo Mail

1. Sign in at https://mail.yahoo.com, click the profile name -> **Account Info**.
2. **Account Security** (left menu). Turn on **2-step verification** if it is off.
3. Scroll to **App passwords** -> **Generate app password** (older UI: "Generate
   and manage app passwords").
4. App name: `Secureddy`. Click **Generate**.
5. Copy the 16-character password. It is shown once.
6. In Secureddy: **Add mailbox -> Yahoo**, enter the address and this
   password. The product tests the login before saving.

To revoke later: same page -> delete the app password. The worker will report
`AuthExpired` and the dashboard will ask to reconnect.

Yahoo also exposes "Allow apps that use less secure sign-in". Leave it **off**;
app passwords do not need it.

## iCloud Mail

1. Go to https://appleid.apple.com (now https://account.apple.com) and sign in.
2. Two-factor authentication must be on (it is for all recent Apple IDs).
3. **Sign-In and Security -> App-Specific Passwords -> Generate an
   app-specific password** (the "+" button).
4. Label: `Secureddy`. Enter the Apple ID password when asked.
5. Copy the password (format `xxxx-xxxx-xxxx-xxxx`).
6. In Secureddy: **Add mailbox -> iCloud**, address = the Apple ID email
   (or an @icloud.com alias), password = the app-specific password.

Limits: Apple allows 25 active app-specific passwords. Changing the Apple ID
password revokes all of them; the client will need to generate a new one.

Note on **Apple Lockdown Mode**: it does not affect IMAP from our side. We
recommend clients turn it on (see `security-model.md`).

## Outlook.com (Hotmail, Live, MSN)

1. Go to https://account.microsoft.com/security -> **Advanced security options**.
2. **Two-step verification** must be **on**. App passwords are only offered
   when it is.
3. Under **App passwords** -> **Create a new app password**.
4. Copy the password. Name it in your own notes; Microsoft does not label them.
5. In Secureddy: **Add mailbox -> Outlook.com**, address + app password.

Microsoft has been retiring basic authentication for consumer IMAP. If the
login fails with an authentication error although the password is right, the
account has lost basic-auth IMAP and the only path is OAuth with a Microsoft
Entra app registration (`IMAP.AccessAsUser.All`). That is a future connector;
for now tell the client and offer Gmail forwarding as a stopgap.

## HOLD mode: the filter the client creates

In **Scan** mode mail reaches the inbox at once and gets labels afterwards. In
**Hold** mode mail must land in a folder we control first. Gmail does this with
a filter we create through the API. IMAP providers have no filter API, so the
client creates one rule by hand:

**Yahoo**

1. Settings (gear) -> **More Settings -> Filters -> Add new filters**.
2. Filter name: `Secureddy hold`.
3. Set the rule: *From* `contains` `@` (matches every sender).
4. **Choose a folder to move to**: `Secureddy/Checking` (create the folder
   first: Folders -> "+ New folder" -> `Secureddy`, then a subfolder
   `Checking`). If the UI does not do nested folders, name it
   `Secureddy - Checking`; the product accepts both.
5. Save. New mail now skips the inbox and waits in `Checking`; the worker
   moves it to the inbox with a verdict label, or to `Quarantine`.

**iCloud**

iCloud.com -> Mail -> gear -> **Settings -> Rules -> Add a rule**:
*If a message* `is addressed to` `<the client's address>` -> *Then* `Move to
Folder` -> `Secureddy/Checking`. Rules only run on iCloud.com/Mail server
side when created on the web, not in the Mac Mail app.

**Outlook.com**

Settings -> **Mail -> Rules -> Add new rule**: condition *To* = the address,
action *Move to* `Secureddy/Checking`, and keep "Stop processing more
rules" on.

The product creates the folders itself during setup (`MailboxConnector.setup`)
so the client only has to point the rule at them. **Teardown** (switching back
to Scan, or leaving the service) does not remove the rule; the client deletes
it, and the product shows a reminder until mail stops arriving in `Checking`.

## The dead man's switch and IMAP

If the worker stops for `RS_HOLD_DEAD_MAN_MINUTES` (10), the deadman process
moves everything in `Checking` back to the inbox (`release_all_pending`). With
IMAP this is a plain MOVE/COPY+EXPUNGE; it works as long as the app password
is still valid. If the password was revoked, mail stays in `Checking` and the
client must move it by hand. That is why expired IMAP credentials page the
on-call immediately (`operations-runbook.md`).

## Telling clients what to expect

- Mail in **Hold** mode arrives a little later: usually under 30 s, up to
  `hold_timeout_s` (120 s) when a detonation is slow.
- They will see new folders named `Secureddy/...` in every mail app.
  That is on purpose.
- Nothing is deleted. Quarantine is a folder; they can move mail out of it.
