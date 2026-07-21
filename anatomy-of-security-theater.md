# Anatomy of Security Theater
### Vue Template Injection and a Chain of Failed Mitigations

> *A coordinated-disclosure case study. The target is anonymized as a high-traffic Polish media
platform. \
> Proof-of-concept only — no user data was accessed and no service was disrupted. Working
exploit payloads are deliberately omitted; this write-up is about reasoning, not weaponization.*

---

## TL;DR

A stored XSS via client-side template injection (Vue) in a comment field could be chained with
missing security headers and an unvalidated client-side asset cache into a full account-takeover
path. The more instructive part is what happened afterwards: a sequence of vendor "fixes" —
character-stripping filters and an `eval`-override script — that each treated a symptom while
leaving the root cause (unsafe rendering of user input, and no Content-Security-Policy) untouched.
This is a walk through the vulnerability, the chain, and why every mitigation was theater.

---

## The core vulnerability: client-side template injection

Comment content was rendered such that Vue template expressions (`{{ ... }}`) were evaluated rather
than displayed, allowing arbitrary JavaScript to execute in the viewer's authenticated session.
Because comments are stored, the payload ran for every user who opened the post.

- **Class:** CWE-79 (XSS) via CWE-1336 (template injection)
- **Entry point:** stored, in the comment body

## The chain

A note on session handling first, because it shapes everything below: the session cookie carried
`HttpOnly` and `Secure`. That was done **correctly** — token theft via JavaScript was off the
table. So the interesting impact was never session hijacking; it was **credential capture**.

1. **Code execution** — the template injection above.
2. **Credential capture** — two independent techniques, the same outcome, and the same underlying
   gap (missing headers as the defensive layer that would have contained them):
   - *Autofill abuse (zero interaction):* an injected fake login form triggers the browser's
     password-manager autofill; injected script reads the populated values through DOM observation.
     An open tab is sufficient — no click, no typing.
   - *UI-redressing / phishing:* with no `X-Frame-Options` or `frame-ancestors`, a fake login
     surface can be framed over the page to capture submitted credentials.
3. **Persistence** — a media-player sprite asset cached in `localStorage` was loaded without any
   integrity check, so a poisoned variant re-executed on nearly every page view across a
   media-heavy site. This is post-exploitation (it needs a prior execution vector), not an entry
   point.

**Why the composition matters:** each weakness is unremarkable in isolation. Composed, they yield
account takeover *plus* password-reuse exposure across other services. Per-finding severity scoring
systematically understates chained risk — severity is a property of the composition, not of the
individual findings.

---

## The interesting part: a lifecycle of failed mitigations

### 1. Stripping template braces

The first fixes removed `{{ }}` brace pairs from input. Because the filter removed only *pairs*,
nesting the expression more deeply restored valid template syntax after filtering — each successive
patch merely raised the number of pairs required, without changing anything fundamental. Eventually
the filter was changed to strip *all* brace pairs, which blocked the known vector. The decision that
caused the bug — rendering user input in a template-evaluating context — was never revisited.

*(Working bypasses are omitted by design. The point is the pattern: a denylist tuned to the exact
tokens seen in a PoC is not a fix, it is a delay.)*

### 2. Regex "sanitization" of HTML

Client-side code stripped HTML tags with regular expressions, then **rebuilt** HTML (mention links)
by string concatenation with user-derived values and no context-aware encoding. The shape of the
anti-pattern:

```js
// strip tags, then reconstruct HTML by concatenation — the wrong order, twice over
text = text.replace(/<[^>]+>/g, '');
text = text.replace(/@\[(\w+)\]/g, (_, name) => `<a href="/user/${name}">@${name}</a>`);
```

Two textbook problems: regex is the wrong tool for HTML (HTML is not a regular language — an OWASP
evergreen), and re-introducing HTML by concatenation *after* stripping inverts the correct order and
hands back the injection surface the strip was meant to remove. Doing this on a field labelled as
already "safe" by the backend also blurs where the security boundary actually lives.

### 3. Overriding `eval` instead of shipping a policy

A script neutralized `window.eval` (and, in one area, `Function.prototype.constructor`):

```js
Object.defineProperty(window, 'eval', { value: () => {}, writable: false });
```

This is not a substitute for CSP. Code execution in a browser requires neither `eval` nor
`Function.prototype.constructor`; blocking narrow primitives leaves the real policy layer — CSP and
framing headers — entirely absent. An external header scan confirmed no `Content-Security-Policy`,
no `X-Frame-Options`, and no `X-Content-Type-Options`.

---

## What correct remediation looks like

- **Output encoding, not character filtering.** Encode contextually; if HTML must be allowed,
  sanitize server-side with a vetted allowlist library — never rebuild HTML by concatenation.
- **Ship a real policy.** `Content-Security-Policy` (drop `unsafe-inline`, restrict `script-src`),
  `X-Frame-Options: DENY` / `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`.
- **Distrust client storage.** Never render or execute content sourced from `localStorage` without
  integrity validation.

## Takeaways

- **Fix the class, not the character.** Removing the exact tokens from a PoC delays the next
  incident; it does not prevent it.
- **Defense-in-depth is not optional.** `HttpOnly` + `Secure` on the session cookie were correct and
  meaningfully raised the bar. The absence of CSP and framing headers gave most of that ground back.
- **Severity lives in compositions.** Three "low" findings composed to "critical."

---

## Disclosure & ethics

Good-faith research; the findings were reported to the operator. Proof-of-concept only — no user
data was accessed, no data modified, no service disrupted. The target is anonymized here and working
exploit payloads are withheld. The intent of this write-up is educational: how remediation goes
wrong, and what addressing a root cause actually requires.
