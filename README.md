# Tanur — engine & reference client

> **فارسی پایین‌تر.** Persian version below.

Tanur is an anti-censorship transport engine: a secure, multiplexed channel that
hides inside ordinary-looking HTTPS and is shaped to resemble real web traffic.
This repository is the **protocol engine and a reference client** — the parts
whose security does not depend on secrecy.

## What this is

- **`inner/`** — the secure channel: a Noise (`flynn/noise`) handshake, framing,
  and multiplexing over any byte stream.
- **`skin/`** — the outer TLS "skin": a real TLS 1.3 session to a real domain
  that serves a real site; a client that proves a shared "door" is upgraded to
  the inner channel, while a browser just gets the website.
- **`recipe/`** — the on-wire *recipe* format (distributions, not fixed
  constants) and its signature **verification**; plus the per-session sampler.
- **`internal/shaper/`** — the traffic shaper: it targets *structure*
  (multiplexing, asymmetry, periodic bursts), not single-packet randomness.
- **`carrier/`, `tunnel/`** — a CDN-frontable HTTP carrier and a SOCKS5 exit.
- **`brain/`** — the **client-side** path selection (a ladder with a per-operator
  penalty box) and assignment **verification**.
- **`engine/`** — the single entry point an app embeds: fetch a signed endpoint
  list, ladder across carriers, run the shaped channel, expose a local SOCKS5
  proxy, fail over transparently.
- **`cmd/`** — reference binaries: `tanur-cli` (the reference client), plus small
  reference servers for running the protocol end-to-end locally.

## What this is NOT

Tanur's resistance to blocking comes from **live operations**, not code secrecy.
By design, this repository does **not** include the operational control plane:

- the server-side "brain"/tactics (the fleet pool, the per-user signed endpoint
  subset, and the selection/steering policy);
- the **recipe factory** and any recipe-signing private keys;
- the server-fleet automation and deployment configuration;
- the in-country sentinel (measurement) network and its collected data.

These are intentionally withheld. The engine is fully functional without them;
you supply your own endpoints and recipes.

## Security model (Kerckhoffs)

The protocol is designed to be safe **even with fully public code**. Safety comes
from:

1. the **Noise handshake** — standard, well-reviewed cryptography. We do not
   invent cryptography; only `golang.org/x/crypto`, `flynn/noise`, `crypto/tls`,
   and uTLS are used.
2. **live operational variance** — signed recipes and server-side steering change
   the on-wire structure over time, so there is no fixed signature to fingerprint.

Publishing the engine does not weaken either property. See
[`docs/inner-protocol-v0.md`](docs/inner-protocol-v0.md) and
[`docs/dpi-and-shaper-requirements.md`](docs/dpi-and-shaper-requirements.md).

## Build & test

Requires Go 1.27+.

```bash
go build ./...
go test ./...
```

## Releases are signed

Official releases are signed and published through one official channel. Builds
distributed under the name "Tanur" from anywhere else may be hostile. See
[`NOTICE`](NOTICE) and [`RELEASING.md`](RELEASING.md).

## License

[MPL-2.0](LICENSE). Security disclosure: [`SECURITY.md`](SECURITY.md).
Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

# تنور — موتور و کلاینتِ مرجع

تنور یک موتورِ انتقالِ ضدسانسور است: یک کانالِ امنِ چندجریانی که داخلِ یک
HTTPSِ معمولی پنهان می‌شود و شکلش طوری تنظیم می‌شود که مثلِ ترافیکِ واقعیِ وب
به نظر برسد. این مخزن **موتورِ پروتکل و یک کلاینتِ مرجع** است — بخش‌هایی که
امنیت‌شان به پنهان‌بودن وابسته نیست.

## این چیست

- **`inner/`** — کانالِ امن: دست‌دادنِ نویز، قاب‌بندی و چندجریانی روی هر جریانِ بایت.
- **`skin/`** — پوستهٔ بیرونیِ تی‌ال‌اس: یک تی‌ال‌اس ۱٫۳ِ واقعی به دامنه‌ای واقعی
  که سایتِ واقعی سرو می‌کند؛ کلاینتی که «در» را ثابت کند به کانالِ درونی ارتقا
  می‌یابد، و مرورگر فقط سایت را می‌بیند.
- **`recipe/`** — فرمتِ *دستور پخت* (توزیع‌ها، نه ثابت‌ها) و **تأییدِ** امضای آن.
- **`internal/shaper/`** — شکل‌دهنده: **ساختار** را هدف می‌گیرد (چندجریانی،
  نامتقارنی، قطعه‌های دوره‌ای)، نه تصادفی‌کردنِ تک‌پکت.
- **`carrier/`, `tunnel/`** — حاملِ HTTPِ پشتِ سی‌دی‌ان و خروجیِ SOCKS5.
- **`brain/`** — انتخابِ مسیرِ **سمتِ کلاینت** و **تأییدِ** تخصیص.
- **`engine/`** — تنها دری که اپ استفاده می‌کند.
- **`cmd/`** — باینری‌های مرجع.

## این چه **نیست**

مقاومتِ تنور از **عملیاتِ زنده** می‌آید، نه از پنهان‌بودنِ کد. این مخزن عمداً
کنترل‌پلینِ عملیاتی را **ندارد**: مغز/تاکتیکِ سمتِ سرور، کارخانهٔ دستور پخت و
کلیدهای امضا، خودکارسازیِ ناوگان، و شبکهٔ حسگرِ داخلِ کشور و داده‌اش. موتور بدونِ
این‌ها کاملاً کار می‌کند؛ نقطه‌پایان و دستور پخت را خودت می‌دهی.

## مدلِ امنیتی (کرکخوف)

پروتکل طوری طراحی شده که **حتی با کدِ کاملاً عمومی** امن باشد: امنیت از دست‌دادنِ
نویز (رمزنگاریِ استاندارد) و از تنوعِ عملیاتیِ زنده (دستورهای پختِ امضاشده +
هدایتِ سرور) می‌آید. رمزنگاری اختراع نمی‌کنیم.

## ساخت و تست

به Go 1.27+ نیاز است: `go build ./...` و `go test ./...`.

## انتشارها امضا می‌شوند

انتشارهای رسمی امضا می‌شوند و از یک کانالِ رسمی می‌آیند. به [`NOTICE`](NOTICE)
نگاه کن. مجوز: [MPL-2.0](LICENSE).
