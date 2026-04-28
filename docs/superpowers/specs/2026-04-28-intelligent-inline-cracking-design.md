# Intelligent Inline Cracking Design

## Goal

Replace the single wordlist-path prompt in D1 inline cracking with a staged attack sequence that maximises crack rate with minimal operator input: SSID mutations run automatically first, then rockyou + best64.rule, then a custom path. GPU detection is intentionally omitted — hashcat handles device selection on its own.

## Architecture

Three files changed, one new file created. No new packages.

| File | Role |
|------|------|
| `internal/controller/cracking_intel.go` | New: `GenerateSSIDWordlist`, `CommonWordlistPaths`, `BestRulePath` |
| `internal/controller/cracking.go` | Add `rules []string` param to `RunHashcat`; update args assembly |
| `internal/controller/assessment.go` | Rewrite `HandleD1PostRun` with staged sequence |
| `internal/controller/cracking_test.go` | Add `TestGenerateSSIDWordlist`, `TestCommonWordlistPaths`; update existing `RunHashcat` call sites to pass `nil` rules |

---

## cracking_intel.go — New Helpers

### GenerateSSIDWordlist

```go
func GenerateSSIDWordlist(ssid, outputPath string) error
```

Returns an error if `ssid` is empty (caller skips Stage 1). Otherwise writes a file at `outputPath` containing ~25 SSID-derived candidate passwords:

- Exact SSID
- `ssid123`, `ssid1234`, `ssid12345`
- `ssid2024`, `ssid2025`, `ssid2026`
- `ssid!`, `ssid#1`, `ssid@1`
- All-lowercase variant, all-uppercase variant, title-case variant
- Each of the above prefixed or suffixed with `1`, `01`, `2024`, `2025`
- Deduplication (case variants only if distinct from original)

### CommonWordlistPaths

```go
func CommonWordlistPaths() []string
```

Returns a slice of discovered rockyou paths, in priority order:

```
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/rockyou.txt.gz   (not used — listed for completeness)
/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
/opt/wordlists/rockyou.txt
```

Only paths where `os.Stat` succeeds are returned. Empty slice is valid — caller handles the "not found" case.

### BestRulePath

```go
func BestRulePath() string
```

Returns the path to `best64.rule` if found at any standard hashcat location:

```
/usr/share/hashcat/rules/best64.rule
/usr/lib/hashcat/rules/best64.rule
/usr/local/share/hashcat/rules/best64.rule
```

Returns `""` if not found. Caller passes `nil` rules to `RunHashcat` in that case — Stage 2 runs without rules rather than failing.

---

## cracking.go — RunHashcat Signature Change

**Before:**
```go
func RunHashcat(ctx context.Context, captureFile, wordlist, mode, logFile string, execMgr *executor.Manager) (*CrackResult, error)
```

**After:**
```go
func RunHashcat(ctx context.Context, captureFile, wordlist, mode, logFile string, rules []string, execMgr *executor.Manager) (*CrackResult, error)
```

Rules are appended to args as `--rules-file <r>` entries. `nil` or empty slice passes no rules.

The only existing call site is `HandleD1PostRun` in `assessment.go` — it is rewritten in this feature. No other callers exist.

---

## assessment.go — HandleD1PostRun Staged Sequence

### Stage 1 — SSID Mutations (automatic, no prompt)

1. Read SSID from session DB (`GUEST_SSID` config key).
2. If SSID is empty: print `[*] No SSID set — skipping SSID mutation stage.` and proceed to Stage 2.
3. Call `GenerateSSIDWordlist(ssid, filepath.Join(evidenceDir, "D1_ssid_wordlist.txt"))`.
4. Run `RunHashcat` with a 30-second context timeout, `rules: nil`.
5. If PSK found: record credential, print result, return.
6. If not found: print `[*] SSID mutations: no match (Xs). Trying rockyou...` and fall through.

### Stage 2 — Rockyou + best64.rule (prompted or path-prompted)

1. Call `CommonWordlistPaths()`.
2. **If rockyou found:**
   - Print `[?] Run rockyou + best64.rule? (~N min on CPU) [Y/n]`
   - If operator declines: skip to Stage 3.
   - Run `RunHashcat` with `rules: []string{BestRulePath()}` (or `nil` if best64 not found), no timeout.
3. **If rockyou not found:**
   - Print `[*] rockyou not found. Enter wordlist path (or Enter to skip):`
   - Read path. If empty: skip to Stage 3.
   - Validate path exists.
   - Run `RunHashcat` with `rules: nil` (custom path, no rules assumed), no timeout.
4. If PSK found: record credential, print result, return.
5. If not found: fall through to Stage 3.

### Stage 3 — Custom Wordlist (prompted)

1. Print `[?] Enter custom wordlist path (or Enter to skip):`
2. If empty: print `Skipping — capture file saved for offline use.` and return.
3. Validate path exists. If not: print error and return.
4. Run `RunHashcat` with `rules: nil`, no timeout.
5. If PSK found: record credential, print result.
6. If not found: print exhausted message.

### Credential Recording (unchanged)

Same as current: `INSERT INTO credential` with `tc_id="D1"`, SSID as username, PSK as password, BSSID as target_host. Regardless of which stage found it.

---

## Exit Codes and Early Return

Each stage returns from `HandleD1PostRun` immediately on `result.Found == true`. Stages 2 and 3 are unreachable once a PSK is found.

---

## Testing

**`TestGenerateSSIDWordlist`** (new):
- Call with `ssid = "CorpWifi"`, verify output file contains `"CorpWifi"`, `"corpwifi"`, `"CORPWIFI"`, `"CorpWifi123"`, `"CorpWifi2025"` and has no duplicate lines.
- Call with `ssid = ""`, verify error returned and no file written.

**`TestCommonWordlistPaths`** (new):
- Call and verify return type is `[]string` (content not asserted — test machines won't have rockyou).

**`TestBestRulePath`** (new):
- Call and verify return type is `string` (content not asserted — test machines won't have hashcat rules).

**Existing `RunHashcat` tests:**
- Add `nil` as the `rules` argument to all existing call sites in `cracking_test.go`. No behaviour change.
