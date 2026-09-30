# Go to market

Target: **$100 USD**. Everything below assumes $0 capital — no ads, no domains, no
inventory.

## What's live

| | |
| --- | --- |
| Source | https://github.com/ihsieh31/pastesafe |
| Landing page | https://ihsieh31.github.io/pastesafe/ |
| Install | `npm i -g pastesafe` — *needs an npm publish, see checklist* |

## The offer ladder

$100 is a small number. A product with no audience sells zero copies, so the money has
to come from a high-ticket item that one buyer can cover on its own.

| Offer | Price | Effort to deliver | Notes |
| --- | --- | --- | --- |
| Secret Exposure Audit | **$199** | ~2h of me doing it | 1 sale = 2× the target. Sells on fear, not features. |
| PasteSafe — Team licence | $99 | already built | 1 sale = target. Needs a payment account. |
| PasteSafe — CLI | $19 | already built | Needs ~6 sales. Only viable with traffic. |

Lead with the Audit. The CLI is the credibility that makes the Audit believable.

## The Audit, in one paragraph

Someone hands over a repo. I scan the working tree *and* the full git history for
credentials that were committed and later "removed" but are still in the object store.
They get a written report: what leaked, where, since when, blast radius, and the exact
rotation order. This is a real incident-prevention service, not a code review.

## Channels

Ordered by realistic conversion for a seller with zero followers.

1. **Communities that already have the fear.** `r/SideProject`, `r/webdev`, `r/devops`,
   `r/selfhosted`. Post the free tool, mention the audit in one line. Do not drop a
   link-only post; show a real redacted terminal screenshot.
2. **Places people hire.** `r/forhire`, V2EX 委託區, 蝦皮 / 104  freelancer boards.
   The Audit is a service, so it belongs here.
3. **Show HN / Product Hunt.** High variance, one good shot. Submit the free CLI, link
   the paid tier from the README. Expect 0–3 sales, occasionally more.
4. **Direct outreach.** Find teams whose public repos have a real committed key.
   That is a genuinely useful, non-spammy email: "your `config/prod.env` in commit
   `a3f9c21` is a live key; here's a free scan." The free report is the pitch.

## Ready-to-post copy

### English — community post

> Built a CLI that reads what you're about to paste into ChatGPT/Claude and tells you
> what's about to leak.
>
> I pasted a stack trace last month that had a live Stripe key in it. Cost me a
> weekend and a very uncomfortable call. So I wrote `pastesafe`.
>
> ```
> $ pbpaste | pastesafe
>   CRITICAL github.pat            2:14
>            GITHUB_TOKEN=«github.pat#0867c742»
>   HIGH     pii.credit-card       5:15 verified
>            CUSTOMER_CARD=«pii.credit-card#ed688096»
> ```
>
> It runs offline, zero dependencies, and the redaction is one-way — there's no
> function in it that turns a placeholder back into a secret. Card numbers are
> Luhn-checked and TW national IDs are checksum-validated, so it doesn't cry wolf.
>
> MIT, `npm i -g pastesafe`. If you'd rather someone just look at your repo for
> this kind of thing, that's a $199 audit — DM me.

### 繁體中文 — 社群貼文

> 寫了一個小工具：在你把東西貼到 ChatGPT / Claude 之前，先掃一遍會不會洩漏。
>
> ```
> $ pbpaste | pastesafe
>   CRITICAL github.pat      2:14
>            GITHUB_TOKEN=«github.pat#0867c742»
>   HIGH     pii.credit-card 5:15 verified
>            CUSTOMER_CARD=«pii.credit-card#ed688096»
> ```
>
> 完全離線、零依賴。遮罩是單向的——程式裡沒有任何函式能把 placeholder 還原成
> 真正的 key。信用卡號會跑 Luhn、居護證會跑 mod-10 檢查，所以不會亂叫。
>
> MIT 授權，`npm i -g pastesafe`。想讓人直接幫你掃整個 repo 的話，這是 $199 的服務，
> 私訊我。

### Direct outreach — the one that converts

> Hi — commit `a3f9c21` in `<repo>` added what looks like a live AWS access key
> (`AKIA…`, still valid when I checked). It's in the history even though it's gone
> from the current tree, so deleting the file doesn't fix it.
>
> Two things worth doing today: rotate the key, then assume it was public since that
> commit's date.
>
> If you want the whole history scanned, that's a $199 audit — I check every commit
> and every path, and you get a written report with rotation order. Happy to just do
> that one file for free if you'd rather start there.

## Setup checklist

Only the first two are still open.

- [x] GitHub repo, public, CI green on Node 18/20/22/24
- [x] Landing page live on GitHub Pages
- [ ] `npm publish` — needs a free npm account, then `npm publish` in the repo
- [ ] Open a payout account: **Payoneer** (best for TW) or **PayPal Taiwan**
- [ ] `STRIPE_SECRET_KEY=… node setup/launch.mjs`, or create the three products by
      hand on Gumroad / Lemon Squeezy
- [ ] Paste the checkout links into `web/index.html`
- [ ] Post to 3 communities, spaced a day apart

## Honest expectations

- Publishing to npm takes 10 minutes; the first organic download is days, not hours.
- The Audit is the realistic path to $100 in under a week, and it depends on outreach
  landing, not on the code being good.
- Every payment route has a delay. PayPal and Stripe hold funds for new accounts
  before releasing them, and bank transfer adds 1–3 business days. Money that arrives
  today will not be in a Taiwanese account the same morning.
