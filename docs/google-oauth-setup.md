# Google OAuth and Gmail setup

What you get at the end: a Google OAuth client (id + secret) that lets a
client sign in and lets Secureddy read, label and move their Gmail, plus a
Pub/Sub topic that pushes "new mail" events to the worker in seconds.

Time: about 45 minutes for the first project. Verification takes weeks; start
it early (section 6).

## 1. Create the GCP project

1. Go to https://console.cloud.google.com and sign in with the Google account
   that will own the product (not a client's account).
2. Project picker (top left) -> **New project**. Name: `secureddy`.
   Organization: none is fine.
3. Wait for the project to be created, then select it.

## 2. Enable the APIs

APIs & Services -> **Library**. Enable:

- **Gmail API**
- **Cloud Pub/Sub API** (for push notifications)

## 3. OAuth consent screen

APIs & Services -> **OAuth consent screen** (now under "Google Auth Platform").

| Field | Value |
|-------|-------|
| User type | **External** (clients have personal @gmail.com accounts) |
| App name | `Secureddy` |
| User support email | your address |
| App logo | optional; adding one triggers brand verification (fine, we need it anyway) |
| App domain, home page | `https://app.<your-domain>` |
| Privacy policy | `https://app.<your-domain>/privacy` (must be on a domain you verify) |
| Terms of service | `https://app.<your-domain>/terms` |
| Authorized domains | `<your-domain>` |
| Developer contact | your address |

Save and continue.

### Scopes

Add exactly these and nothing more. Fewer scopes = less verification work.

| Scope | Why | Class |
|-------|-----|-------|
| `openid` | sign-in | non-sensitive |
| `email` | sign-in | non-sensitive |
| `profile` | display name | non-sensitive |
| `https://www.googleapis.com/auth/gmail.modify` | read mail, add/remove labels, move to and from the inbox (quarantine, hold, release) | **restricted** |
| `https://www.googleapis.com/auth/gmail.settings.basic` | create the HOLD filter that parks new mail under `Secureddy/Checking` | sensitive |
| `https://www.googleapis.com/auth/gmail.labels` | create the `Secureddy/*` labels | non-sensitive |

We do not ask for `mail.google.com` (full access) or `gmail.send`.

### Test users

While the app is in **Testing** status:

- Add yourself and your brother under **Test users** (up to 100 addresses).
- Only test users can sign in.
- **Refresh tokens expire after 7 days.** Every mailbox has to be reconnected
  weekly until the app is **In production**. The worker reports this as
  `AuthExpired`; the dashboard shows "Reconnect Gmail". Plan for verification
  (section 6) right away because of this.

## 4. Create the OAuth client

APIs & Services -> **Credentials** -> **Create credentials** -> **OAuth client ID**.

| Field | Value |
|-------|-------|
| Application type | **Web application** |
| Name | `reddysec-web` |
| Authorized JavaScript origins | `http://localhost:8000`, `https://app.<your-domain>` |
| Authorized redirect URIs | `http://localhost:8000/auth/google/callback`, `https://app.<your-domain>/auth/google/callback` |

The redirect path is `RS_GOOGLE_REDIRECT_PATH` (default `/auth/google/callback`)
appended to `RS_BASE_URL`. If you use the `*.azurefd.net` host before DNS is
ready, add that redirect URI too.

Copy the **Client ID** and **Client secret**:

- local: `RS_GOOGLE_CLIENT_ID` / `RS_GOOGLE_CLIENT_SECRET` in `.env`
- Azure: `googleClientId` in `infra/azure/main.<env>.bicepparam`, and the secret
  in Key Vault:

      az keyvault secret set --vault-name <kv> --name rs-google-client-secret --value '<secret>'

  then redeploy (or restart the apps) so the new secret version is picked up.

Use one client for dev and prod if you like; the redirect URI list covers both.
A separate GCP project for dev keeps test users and quotas apart but doubles
the verification work. We use one project.

## 5. Pub/Sub push (new-mail notifications)

Without this the worker polls every `RS_GMAIL_POLL_SECONDS` (15 s). With it,
Gmail pushes within ~1-2 s.

1. Pub/Sub -> **Topics** -> **Create topic**. ID: `reddysec-gmail`.
   Leave "Add a default subscription" unchecked.
2. On the topic -> **Permissions** -> **Add principal**:
   - principal: `gmail-api-push@system.gserviceaccount.com`
   - role: **Pub/Sub Publisher**
3. **Subscriptions** -> **Create subscription**:
   - ID: `reddysec-gmail-push`
   - Topic: `reddysec-gmail`
   - Delivery type: **Push**
   - Endpoint URL:

         https://app.<your-domain>/hooks/gmail/pubsub?token=<rs-pubsub-token>

     `rs-pubsub-token` is the Key Vault secret `bootstrap.sh` generated:

         az keyvault secret show --vault-name <kv> --name rs-pubsub-token --query value -o tsv

   - Enable authentication: optional. The token in the URL is what the app
     checks. If you also enable it, Google signs each push with a service
     account JWT; the app can verify that too later.
   - Acknowledgement deadline: 10 s. Retry policy: exponential backoff.
   - Message retention: 10 minutes (we re-sync from history on reconnect anyway).
4. Set `googlePubsubTopic = 'projects/secureddy/topics/reddysec-gmail'`
   (the full name) in the bicepparam file; locally `RS_GOOGLE_PUBSUB_TOPIC`.

The worker calls `users.watch` per mailbox; a watch lasts 7 days and the worker
renews it. If pushes stop (quota, deleted subscription) the worker falls back to
polling. Front Door's WAF has a separate, higher rate limit for `/hooks/*`.

## 6. Verification: getting out of Testing

Three things, in this order. Budget 4-8 weeks total.

### 6a. Brand verification

Triggered by a logo or by going to production. Google checks the app name,
logo, home page and privacy policy. The privacy policy must live on your own
domain and say what Gmail data is read and that it is not sold. Days to a week.

### 6b. Restricted-scope verification (`gmail.modify`)

APIs & Services -> OAuth consent screen -> **Publish app**, then submit for
verification. You will be asked for:

- a justification per scope (one paragraph each; say exactly what the app does:
  reads new messages, labels them with a verdict, moves suspicious ones out of
  the inbox, moves them back on request);
- a **demo video** (YouTube, unlisted) showing the sign-in, the consent screen,
  and every place Gmail data is used: inbox labels, quarantine, release;
- the privacy policy URL from 6a.

Google replies by email, usually within a week, often with questions.

### 6c. CASA Tier 2 security assessment

Because `gmail.modify` is a restricted scope and the app stores Gmail data
(tokens, metadata) on servers, Google requires a **CASA Tier 2** assessment:

- done by a Google-approved assessor (the list is at
  https://appdefensealliance.dev/casa; several offer a self-scan tier 2 for a
  few hundred dollars, a lab-verified one for more);
- covers OWASP ASVS Level 2 controls: TLS, auth, session handling, secret
  storage, logging, dependency hygiene;
- **renewed every 12 months**, and the letter of validation is uploaded to the
  verification case.

What in this repo answers the usual questions: Key Vault for secrets, envelope
encryption of tokens (`core/crypto.py`), no mail bodies stored
(`store/models.py`), private networking, WAF, audit log, CI with `pip-audit`.
Keep `docs/security-model.md` current; assessors read it.

### Shortcut: Google Workspace internal app

If a client's mail is on a **Google Workspace** custom domain (not
@gmail.com), a consent screen set to **Internal** inside *that* Workspace needs
no verification at all. The OAuth client must live in a GCP project of that
Workspace organization. This is relevant if your brother's mailbox is on a
Workspace domain: a second, internal OAuth client just for his organization
skips brand, scope and CASA review. Personal @gmail.com accounts cannot use an
internal app.

## 7. Quotas to know

- Gmail API: 1,000,000 quota units/day per project, 250 units/second/user.
  A full poll cycle for one mailbox costs roughly 10-60 units. Hundreds of
  mailboxes are fine; check the quota page before onboarding client number 50.
- `users.watch` push: no extra Gmail quota; Pub/Sub free tier covers millions
  of messages a month.
- OAuth: 100 test users in Testing; unlimited in production.

## 8. Checklist

- [ ] Project `secureddy`, Gmail API + Pub/Sub API enabled
- [ ] Consent screen External, app name "Secureddy", 6 scopes, privacy + terms URLs live
- [ ] Test users: you, your brother
- [ ] Web client with localhost + prod redirect URIs; secret in `.env` and Key Vault
- [ ] Topic `reddysec-gmail`, `gmail-api-push@system.gserviceaccount.com` is Publisher
- [ ] Push subscription to `/hooks/gmail/pubsub?token=...`
- [ ] Verification submitted; CASA assessor chosen; calendar reminder at 11 months
