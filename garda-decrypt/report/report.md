# Recovering an Intercepted Message from a Damaged Multi-Layer Encoder

**[STUDENT NAME] ([STUDENT NUMBER])**<br>
TU Dublin, [MODULE CODE / MODULE NAME], [LECTURER NAME]<br>
[DATE OF SUBMISSION]

*Abstract*: An intercepted message and a partially damaged Python 2 program believed to have produced it were analysed. The program applies a random sequence of three reversible transformations (ROT13, base64 and a lowercase Caesar shift) and prefixes each layer with the number of the step used. The ciphertext therefore records how it was made, so the damaged message and round count were not needed. The program was ported to Python 3 and a layer-peeling decoder was written. Decoding recovered the plaintext "Why do elephants have big ears?" after 68 layers (67 random rounds). The result was verified by 1000 random round-trip tests and by re-encoding the recovered plaintext, which reproduced the 35,138-character intercepted ciphertext exactly.

*Index Terms*: ROT13, base64, Caesar cipher, layered encoding, digital forensics, Python 2 to 3 porting.

## I. Introduction

The task was to decode an intercepted message (`intercepted.txt`) using a damaged copy of the encoding program (`encryptme.py`). The damaged parts are marked `&&&&` in the source. This report follows the four assessment criteria. Section II analyses the encryption code. Section III covers the damaged and missing code. Section IV describes decryption and the recovered message. Section V covers the method and verification.

All code, the original files, and the raw outputs quoted in this report are available at:
**https://github.com/Kushal-QA/salted-hash-lab/tree/main/garda-decrypt**

Every trace, count and plaintext in this report comes from running that code. Nothing was typed in by hand. The layer trace in Appendix A was copied programmatically from `output/decrypt_trace.txt`.

## II. Analysis of the Encryption Code

### A. The three steps

**step1** builds a translation table with `string.maketrans` from the alphabet `zyxwvutsrqpon ZYX...PON mlk...a MLK...A` to `mlk...a MLK...A zyx...n ZYX...N`. Reading the pairs gives z→m, n→a, m→z and a→n, and likewise for uppercase. Every letter moves 13 places. This is **ROT13**, written backwards to make it harder to spot. ROT13 is its own inverse because 13 + 13 = 26 [1]. A test confirms that `step1` produces the same output as Python's built-in `rot13` codec (Section V).

**step2** is `b64encode`, standard **base64** [2]. Its inverse is `b64decode`. It is the only step that changes the string's alphabet and length. The output is about 4/3 the length of the input.

**step3** builds a table from `abc...z` to `efg...d`. This is a **Caesar shift of +4 on lowercase letters only** [1]. Uppercase letters, digits and `+/=` are unchanged. The inverse is a shift of -4 (equivalently +22).

None of the steps uses a key. The scheme is an **encoding**, not encryption. Once the algorithm is known, anyone can decode it. Its only protection is keeping the algorithm secret, which goes against Kerckhoffs's principle [1], [6].

### B. `make_secret` and the self-describing prefix

```python
def make_secret(plain, count):
    a = '2{}'.format(b64encode(plain))
    for count in xrange(count):
        r = random.choice(secret_encoding)
        si = secret_encoding.index(r) + 1
        _a = globals()[r](a)
        a = '{}{}'.format(si, _a)
    return a
```

The message is first base64-encoded and prefixed with `'2'`. This is an implicit step-2 layer. Each of the `count` rounds then:

1. picks `step1`, `step2` or `step3` at random;
2. looks up its number `si` (position in `secret_encoding` + 1);
3. applies the step to the **whole** current string, earlier prefix digits included, through `globals()[r]`;
4. **prepends** `si` to the result.

So every layer starts with the number of the step that produced the rest of it. To decode, read the first digit, remove it, apply that step's inverse, and repeat. Steps 1 and 3 only change letters, so the digits of earlier prefixes stay readable. For example, the ciphertext begins `313312M...`. A step-2 round base64-encodes the earlier prefixes, so they reappear only after that layer is decoded. Decoding ends at the innermost `'2'` layer, whose base64 decode gives the plaintext.

### C. Information in the damaged lines

- `secret` is the plaintext we are trying to recover. The comment says its length is unknown too.
- `count` (`count=&&&`) only sets how many rounds were run. The prefixes record each round, so the count is not needed. It can be read from the ciphertext afterwards (67, Section IV).

## III. Handling Damaged and Missing Code

[SCREENSHOT: running `python3 original/encryptme.py` on Kali showing the SyntaxError]

### A. Damaged values

| Damaged item | Treatment | Justification |
|---|---|---|
| `secret = '&&&&...'` | Replaced by a test value (`'This is a test secret'`), overridable from the command line | It is the unknown being recovered and cannot be reconstructed from the code. It is not needed for decoding. |
| `count=&&&` | Replaced by a command-line argument with default 10 | The real count is recorded in the ciphertext prefixes, so it is not needed. Any value works for testing. |

### B. Python 2 to Python 3 port

The original is Python 2. Running it under Python 3 (3.12.10) fails immediately with `SyntaxError: Missing parentheses in call to 'print'`. Kali Linux ships only Python 3. The program was therefore ported to `encryptme_fixed.py` with the logic unchanged. Each change is marked `CHANGE:` in the source.

| Python 2 construct | Python 3 replacement | Reason [5] |
|---|---|---|
| `string.maketrans(a, b)` | `str.maketrans(a, b)` | Removed from the `string` module; now a `str` method [4] |
| `string.translate(s, t)` | `s.translate(t)` | Removed from the `string` module |
| `b64encode(s)` on `str` | `b64encode(s.encode('utf-8')).decode('ascii')` | Python 3 separates bytes and text. `b64encode` takes and returns bytes [3]. |
| `xrange` | `range` | `xrange` removed |
| `print x` | `print(x)` | `print` is a function |

The translation tables, step numbering, prefix format and random-step loop were copied unchanged. The original also reuses the name `count` as the loop variable. This was left as-is because it does not affect behaviour. Python 2 was not available on the test machine, so the original could not be run directly. The port is instead checked by encoding the recovered plaintext with the ported steps, which reproduces the intercepted ciphertext exactly (Section V-B). That shows the port encodes exactly as the program that produced the evidence did.

## IV. Decryption and Message Recovery

### A. Decoder design

`decryptme.py` reads the ciphertext from a file, a command-line string or stdin. It removes all whitespace, since valid layers never contain any, and then peels layers:

| Leading digit | Inverse applied |
|---|---|
| 1 | ROT13 (self-inverse) |
| 2 | strict base64 decode (`validate=True`), result must be valid UTF-8 |
| 3 | lowercase shift by -4 |

Peeling stops when the current string does not start with 1, 2 or 3, or when an inverse fails (for example, invalid base64).

The plaintext itself might start with 1, 2 or 3, so "stop at the first string without a digit" is not a safe stopping rule. The decoder uses the structure of `make_secret` instead. The innermost layer is always `'2' + base64(plain)`, so the plaintext must be the output of a step-2 peel. The decoder peels as far as it can, then takes the **deepest step-2 output** as the plaintext. If it finds no step-2 layer, it reports an error and exits with a non-zero status rather than guessing.

### B. Running the decoder

[SCREENSHOT: running decryptme.py on Kali]

Command: `python3 decryptme.py intercepted.txt --trace output/decrypt_trace.txt --plaintext output/plaintext.txt`

Excerpt of the trace (first and last layers; full trace in Appendix A):

```text
Ciphertext length: 35138 characters
Ciphertext start : 313312Mw16RXtNmlF2TVRmU1pIQxxmnTxtV1ZWV2JFOXBSnFwkVTI5o1ZGWx

Layer  Step inverted                   Length  Result (first 60 chars)
-----------------------------------------------------------------------------------------------------------
    1  step3 (Caesar +4, lowercase)     35137  '13312Ms16RXpNihF2TVRiU1lIQttijTtpV1ZWV2JFOXBSjFsgVTI5k1ZGWtl'
    2  step1 (ROT13)                    35136  '3312Zf16EKcAvuS2GIEvH1yVDggvwGgcI1MJI2WSBKOFwSftIGV5x1MTJgyK'
    3  step3 (Caesar +4, lowercase)     35135  '312Zb16EKyArqS2GIErH1uVDccrsGcyI1MJI2WSBKOFsSbpIGV5t1MTJcuKr'
    4  step3 (Caesar +4, lowercase)     35134  '12Zx16EKuAnmS2GIEnH1qVDyynoGyuI1MJI2WSBKOFoSxlIGV5p1MTJyqKny'
    5  step1 (ROT13)                    35133  '2Mk16RXhNazF2TVRaU1dIQllabTlhV1ZWV2JFOXBSbFkyVTI5c1ZGWldXalZ'
    6  step2 (base64)                   26349  '2MzExMk1vMTZSWHBYZm9aWVVWbE9pRlY2U29sVFZWWjVVMVZ3TVZadlVxcFB'
  ...  (layers 7-61 omitted, see Appendix A)
   62  step3 (Caesar +4, lowercase)        50  '111112I2u5VTEiVTIfMKObLJ50plObLKMyVTWcMlOyLKWmCj=='
   63  step1 (ROT13)                       49  '11112V2h5IGRvIGVsZXBoYW50cyBoYXZlIGJpZyBlYXJzPw=='
   64  step1 (ROT13)                       48  '1112I2u5VTEiVTIfMKObLJ50plObLKMyVTWcMlOyLKWmCj=='
   65  step1 (ROT13)                       47  '112V2h5IGRvIGVsZXBoYW50cyBoYXZlIGJpZyBlYXJzPw=='
   66  step1 (ROT13)                       46  '12I2u5VTEiVTIfMKObLJ50plObLKMyVTWcMlOyLKWmCj=='
   67  step1 (ROT13)                       45  '2V2h5IGRvIGVsZXBoYW50cyBoYXZlIGJpZyBlYXJzPw=='
   68  step2 (base64)                      31  'Why do elephants have big ears?'

Layers peeled: 68
Peel order (outermost first)  : 3 1 3 3 1 2 2 3 1 1 2 2 3 1 2 3 2 2 2 3 3 3 3 3 3 3 2 1 1 3 2 2 1 3 3 2 2 1 1 3 2 1 2 1 1 3 1 2 1 2 3 3 2 3 2 2 3 2 2 1 1 3 1 1 1 1 1 2
Encryption rounds (count)     : 67
Forward step sequence (random rounds, in applied order): 1 1 1 1 1 3 1 1 2 2 3 2 2 3 2 3 3 2 1 2 1 3 1 1 2 1 2 3 1 1 2 2 3 3 1 2 2 3 1 1 2 3 3 3 3 3 3 3 2 2 2 3 2 1 3 2 2 1 1 3 2 2 1 3 3 1 3
Step usage in rounds: step1=22 step2=22 step3=23

Recovered plaintext:
Why do elephants have big ears?
```

### C. Result

The decoder peeled **68 layers**: 67 random rounds plus the initial `'2' + base64(plain)`. The rounds split as step1 = 22, step2 = 22, step3 = 23. The 22 base64 rounds explain why a 31-character message grew to a 35,138-character ciphertext. In the trace, each base64 decode shrinks the layer to about three quarters of its length, for example 6,245 → 4,681 characters at layer 18.

**Recovered message: "Why do elephants have big ears?"**

## V. Method, Verification and Explanation

### A. Method

1. Read the damaged program and identified each step by its translation table and by testing on known input (Section II).
2. Worked out that the leading digit of each layer names the last step applied, so the damaged `count` is not needed.
3. Ported the program to Python 3 and repaired the placeholders (Section III).
4. Wrote the decoder and tested it on ciphertexts from the fixed encryptor before running it on the evidence.
5. Ran it on `intercepted.txt`, then checked the answer independently (below).

### B. Verification

`test_roundtrip.py` was run with Python 3.12.10. Its output is saved in `output/test_results.txt`.

[SCREENSHOT: test_roundtrip.py results on Kali]

- **Step checks**: `step1` equals Python's `rot13` codec and is self-inverse. Each inverse undoes its step. `step3` leaves uppercase letters and digits unchanged. Invalid base64 is rejected.
- **Random round trips**: 1000 secrets (fixed seed 20261121, lengths 1-199) drawn from seven character sets: lowercase, letters, digits, letters+digits, letters+space, punctuation, and printable ASCII. Each used a random count from 0 to 50 (mean 24.4). Each secret was encrypted with `encryptme_fixed.py` and decrypted with `decryptme.py`. All 1000 matched the original, and the number of rounds read from the prefixes matched the count used. **Failures: 0.**
- **Edge cases**: secrets starting with digits (`'1'`, `'2'`, `'3'`, `'123'`, `'1hello'`, ...), non-ASCII text, newlines and tabs, and a 500-character secret. Each was run with counts 0, 1, 5, 25 and 50. All passed.
- **Exact reproduction of the evidence**: the forward step sequence read from the decoding (the peel order reversed, minus the innermost layer) was re-applied to the recovered plaintext with the step functions of `encryptme_fixed.py`. The result was identical to `intercepted.txt`: 35,138 characters, compared character by character. Because the scheme has no key or randomness beyond the recorded step choices, this shows the recovered plaintext produced the intercepted ciphertext. It also confirms the Python 3 port behaves like the original.

Final result: **8 tests run, all passed.**

### C. A failure found during testing

The first test run (kept as `output/test_results_run1_failed.txt`) had one failing edge case. The secret `'2'` decoded as the empty string. The cause is not a decoder bug but a property of the scheme. `make_secret('2', 0)` and `make_secret('', 0)` followed by one step-2 round produce the same ciphertext, `2Mg==`. When two inputs give the same ciphertext, no decoder can tell which one was used. The decoder was given a documented tie-break: prefer the deepest **non-empty** plaintext, since an intercepted message is never empty. A test (`test_ambiguity_empty_vs_2`) now demonstrates the collision. A similar collision is possible whenever a plaintext happens to be a valid layer string itself. That is very unlikely for natural-language text, and it does not affect this case: re-encoding the recovered message reproduces the evidence exactly.

### D. Discussion

The scheme looks complex: 67 rounds turn 31 characters into over 35,000. But layering keyless, reversible encodings adds no secrecy [1]. Each layer names its own inverse, so decoding takes linear time and no search, guessing or cryptanalysis. An effective design would use a keyed, authenticated cipher instead of keeping the algorithm secret [1], [6].

## Code Availability

The original program, intercepted ciphertext, fixed encryptor, decoder, tests and all raw outputs are available at:
**https://github.com/Kushal-QA/salted-hash-lab/tree/main/garda-decrypt**

To reproduce: `python3 decryptme.py intercepted.txt` and `python3 test_roundtrip.py`. Python 3 only, no third-party packages.

## References

[1] W. J. Buchanan, *Cryptography*. Gistrup, Denmark: River Publishers, 2017.

[2] S. Josefsson, "The Base16, Base32, and Base64 Data Encodings," IETF, RFC 4648, Oct. 2006.

[3] Python Software Foundation, "base64: Base16, Base32, Base64, Base85 Data Encodings," *Python 3 Documentation*. [Online]. Available: https://docs.python.org/3/library/base64.html

[4] Python Software Foundation, "Built-in Types: str.maketrans," *Python 3 Documentation*. [Online]. Available: https://docs.python.org/3/library/stdtypes.html#str.maketrans

[5] Python Software Foundation, "What's New In Python 3.0," *Python 3 Documentation*. [Online]. Available: https://docs.python.org/3/whatsnew/3.0.html

[6] A. Kerckhoffs, "La cryptographie militaire," *Journal des sciences militaires*, vol. 9, pp. 5-38, Jan. 1883.

## Appendix A: Full Decryption Trace

Verbatim contents of `output/decrypt_trace.txt`:

```text
Ciphertext length: 35138 characters
Ciphertext start : 313312Mw16RXtNmlF2TVRmU1pIQxxmnTxtV1ZWV2JFOXBSnFwkVTI5o1ZGWx

Layer  Step inverted                   Length  Result (first 60 chars)
-----------------------------------------------------------------------------------------------------------
    1  step3 (Caesar +4, lowercase)     35137  '13312Ms16RXpNihF2TVRiU1lIQttijTtpV1ZWV2JFOXBSjFsgVTI5k1ZGWtl'
    2  step1 (ROT13)                    35136  '3312Zf16EKcAvuS2GIEvH1yVDggvwGgcI1MJI2WSBKOFwSftIGV5x1MTJgyK'
    3  step3 (Caesar +4, lowercase)     35135  '312Zb16EKyArqS2GIErH1uVDccrsGcyI1MJI2WSBKOFsSbpIGV5t1MTJcuKr'
    4  step3 (Caesar +4, lowercase)     35134  '12Zx16EKuAnmS2GIEnH1qVDyynoGyuI1MJI2WSBKOFoSxlIGV5p1MTJyqKny'
    5  step1 (ROT13)                    35133  '2Mk16RXhNazF2TVRaU1dIQllabTlhV1ZWV2JFOXBSbFkyVTI5c1ZGWldXalZ'
    6  step2 (base64)                   26349  '2MzExMk1vMTZSWHBYZm9aWVVWbE9pRlY2U29sVFZWWjVVMVZ3TVZadlVxcFB'
    7  step2 (base64)                   19760  '3112Mo16RXpXfoZYUVlOiFV6SolTVVZ5U1VwMVZvUqpPWEtKTTNWNpIcVpBS'
    8  step3 (Caesar +4, lowercase)     19759  '112Mk16RXlXbkZYUVhOeFV6SkhTVVZ5U1VsMVZrUmlPWEpKTTNWNlIyVlBSa'
    9  step1 (ROT13)                    19758  '12Zx16EKyKoxMLHIuBrSI6FxuGIIM5H1IfZIMeHzyCJRcXGGAJAyVlIyOFn3'
   10  step1 (ROT13)                    19757  '2Mk16RXlXbkZYUVhOeFV6SkhTVVZ5U1VsMVZrUmlPWEpKTTNWNlIyVlBSa3B'
   11  step2 (base64)                   14817  '2MzEyWnFXQXNxUzJHSUVySUl1VkRiOXJJM3V6R2VPRkpKdVN2U0lkRWVFVUl'
   12  step2 (base64)                   11111  '312ZqWAsqS2GIErIIuVDb9rI3uzGeOFJJuSvSIdEeEUIeRou1MJJaMEscWcI'
   13  step3 (Caesar +4, lowercase)     11110  '12ZmWAomS2GIEnIIqVDx9nI3qvGaOFJJqSrSIzEaEUIaRkq1MJJwMEoyWyIy'
   14  step1 (ROT13)                    11109  '2MzJNbzF2TVRaVVdIQk9aV3diTnBSWWdFeFVmRnRHVnExd1ZWWjZRblJlVlZ'
   15  step2 (base64)                    8330  '32Mo1vMTZUWHBOZWwbNpRYgExUfFtGVq1wVVZ6QnReVVV4VnFeg1ZweFRSe3'
   16  step3 (Caesar +4, lowercase)      8329  '2Mk1rMTZUWHBOZWsxNlRYcEtUbFpGVm1sVVZ6QjRaVVV4VjFac1ZsaFRSa3B'
   17  step2 (base64)                    6245  '2Mk16TXpNek16TXpKTlZFVmlUVzB4ZUUxV1ZsVlhTRkpQV20xcVEyZEdVbGR'
   18  step2 (base64)                    4681  '2MzMzMzMzMzJNVEViTW0xeE1WVlVXSFJPWm1qQ2dGUldWcE5TZUUxbGNFVkt'
   19  step2 (base64)                    3508  '33333332MTEbMm1xMVVUWHROZmjCgFRWVpNSeE1lcEVKd2ZyWnVVMVZacVUz'
   20  step3 (Caesar +4, lowercase)      3507  '3333332MTExMi1tMVVUWHROZifCcFRWVlNSaE1hyEVKz2ZuWjVVMVZwyVUvV'
   21  step3 (Caesar +4, lowercase)      3506  '333332MTEtMe1pMVVUWHROZebCyFRWVhNSwE1duEVKv2ZqWfVVMVZsuVUrVg'
   22  step3 (Caesar +4, lowercase)      3505  '33332MTEpMa1lMVVUWHROZaxCuFRWVdNSsE1zqEVKr2ZmWbVVMVZoqVUnVct'
   23  step3 (Caesar +4, lowercase)      3504  '3332MTElMw1hMVVUWHROZwtCqFRWVzNSoE1vmEVKn2ZiWxVVMVZkmVUjVypF'
   24  step3 (Caesar +4, lowercase)      3503  '332MTEhMs1dMVVUWHROZspCmFRWVvNSkE1riEVKj2ZeWtVVMVZgiVUfVulFk'
   25  step3 (Caesar +4, lowercase)      3502  '32MTEdMo1zMVVUWHROZolCiFRWVrNSgE1neEVKf2ZaWpVVMVZceVUbVqhFgE'
   26  step3 (Caesar +4, lowercase)      3501  '2MTEzMk1vMVVUWHROZkhCeFRWVnNScE1jaEVKb2ZwWlVVMVZyaVUxVmdFcE5'
   27  step2 (base64)                    2624  '1132Mo1UTXtNfHBxTVVsRpMchEJofpZUU1VriU1VgEpNREZKZUZGRpNwgGbe'
   28  step1 (ROT13)                     2623  '132Zb1HGKgAsUOkGIIfEcZpuRWbscMHH1IevH1ItRcAERMXMHMTEcAjtTorZ'
   29  step1 (ROT13)                     2622  '32Mo1UTXtNfHBxTVVsRpMchEJofpZUU1VriU1VgEpNREZKZUZGRpNwgGbeM0'
   30  step3 (Caesar +4, lowercase)      2621  '2Mk1UTXpNbHBtTVVoRlMydEJkblZUU1VneU1VcElNREZKZUZGRlNscGxaM0Z'
   31  step2 (base64)                    1965  '2MTMzMlpmMUhFS2tBdnVTSUgyMUpIMDFJeFFFSlplZ3FJMHl2eWdNS0ZoNUp'
   32  step2 (base64)                    1472  '1332Zf1HEKkAvuSIH21JH01IxQEJZegqI0yvygMKFh5JZfkjISIjy2WUJigd'
   33  step1 (ROT13)                     1471  '332Ms1URXxNihFVU21WU01VkDRWMrtdV0liltZXSu5WMsxwVFVwl2JHWvtqR'
   34  step3 (Caesar +4, lowercase)      1470  '32Mo1URXtNedFVU21WU01VgDRWMnpzV0hehpZXSq5WMotsVFVsh2JHWrpmRW'
   35  step3 (Caesar +4, lowercase)      1469  '2Mk1URXpNazFVU21WU01VcDRWMjlvV0dadlZXSm5WMkpoVFVod2JHWnliRWx'
   36  step2 (base64)                    1101  '2MTEzMk1USmVSMUp4V29oWGZvVWJnV2JhTUhwbGZybEllbzF4VTFsSVlVa2N'
   37  step2 (base64)                     824  '1132MTJeR1JxWohXfoUbgWbaMHplfrlIeo1xU1lIYUkcR1FXS0kaSGxbSXFY'
   38  step1 (ROT13)                      823  '132ZGWrE1WkJbuKsbHotJonZUcyseyVrb1kH1yVLHxpE1SKF0xnFTkoFKSLG'
   39  step1 (ROT13)                      822  '32MTJeR1JxWohXfoUbgWbaMHplfrlIeo1xU1lIYUkcR1FXS0kaSGxbSXFYTU'
   40  step3 (Caesar +4, lowercase)       821  '2MTJaR1JtWkdXbkUxcWxwMHlhbnhIak1tU1hIYUgyR1FXS0gwSGtxSXFYTUt'
   41  step2 (base64)                     614  '12ZGRmZGWnE1qlp0yanxHjMmSXHaH2GQWKH0HkqIqXMKHjpwV1AKEUG0SVZ1'
   42  step1 (ROT13)                      613  '2MTEzMTJaR1dyc0lnakUwZzFKUnU2TDJXU0UxdVdKZXUwcjI1NXRHT0FIM1J'
   43  step2 (base64)                     457  '11312ZGWrsIgjE0g1JRu6L2WSE1uWJeu0r255tGOAH3Rns1AoFcg4L2WWH0c'
   44  step1 (ROT13)                      456  '1312MTJefVtwR0t1WEh6Y2JFR1hJWrh0e255gTBNU3Eaf1NbSpt4Y2JJU0py'
   45  step1 (ROT13)                      455  '312ZGWrsIgjE0g1JRu6L2WSE1uWJeu0r255tGOAH3Rns1AoFcg4L2WWH0clF'
   46  step3 (Caesar +4, lowercase)       454  '12ZGWnoIcfE0c1JRq6L2WSE1qWJaq0n255pGOAH3Rjo1AkFyc4L2WWH0yhFQ'
   47  step1 (ROT13)                      453  '2MTJabVpsR0p1WEd6Y2JFR1dJWnd0a255cTBNU3Ewb1NxSlp4Y2JJU0luSDJ'
   48  step2 (base64)                     338  '12ZmZlGJuXGzcbEGWIZwtknyq0MSq0oSqJZxcbISInH2jkoTEKqTk0n0I4I1'
   49  step1 (ROT13)                      337  '2MzMyTWhKTmpoRTJVMjgxald0ZFd0bFdWMkpoVFVaU2wxbGRXdGx0a0V4V1Z'
   50  step2 (base64)                     251  '332MhJNjhE2U281jWtdWtlWV2JhTUZSl1ldWtltkExWVvFqS1IgRtlXjhtXV'
   51  step3 (Caesar +4, lowercase)       250  '32MdJNfdE2U281fWpzWphWV2JdTUZSh1hzWphpgEtWVrFmS1IcRphXfdpXVq'
   52  step3 (Caesar +4, lowercase)       249  '2MzJNbzE2U281bWlvWldWV2JzTUZSd1dvWldlcEpWVnFiS1IyRldXbzlXVm8'
   53  step2 (base64)                     186  '32Mo16So5mioZWVWbsMFRwWoZWepJVVqbKR2FWWo9WVo51Vqw5V2NIUphWWE'
   54  step3 (Caesar +4, lowercase)       185  '2Mk16Sk5iekZWVWxoMFRsWkZWalJVVmxKR2FWWk9WVk51Vms5V2NIUldWWEJ'
   55  step2 (base64)                     137  '2MzJNbzFVUlh0TlZFVjRUVlJGaVZOVVNuVk9WcHRWVXBnYlYxWkZmSEZVVlh'
   56  step2 (base64)                     102  '32Mo1URXtNVEV4TVRFiVNUSnVOVptVUpgbV1ZFfHFUVXRQWqx4S05UQnBnRT'
   57  step3 (Caesar +4, lowercase)       101  '2Mk1URXpNVEV4TVRFeVNUSjVOVlpVUlcxV1ZFbHFUVXRQWmt4S05UQjBjRTl'
   58  step2 (base64)                      73  '2MTEzMTExMTEySTJ5NVZURW1WVElqTUtPZkxKNTB0cE9mTEtNY1ZUV2dNcE9'
   59  step2 (base64)                      53  '113111112I2y5VTEmVTIjMKOfLJ50tpOfLKMcVTWgMpOcLKWqCn=='
   60  step1 (ROT13)                       52  '13111112V2l5IGRzIGVwZXBsYW50gcBsYXZpIGJtZcBpYXJdPa=='
   61  step1 (ROT13)                       51  '3111112I2y5VTEmVTIjMKOfLJ50tpOfLKMcVTWgMpOcLKWqCn=='
   62  step3 (Caesar +4, lowercase)        50  '111112I2u5VTEiVTIfMKObLJ50plObLKMyVTWcMlOyLKWmCj=='
   63  step1 (ROT13)                       49  '11112V2h5IGRvIGVsZXBoYW50cyBoYXZlIGJpZyBlYXJzPw=='
   64  step1 (ROT13)                       48  '1112I2u5VTEiVTIfMKObLJ50plObLKMyVTWcMlOyLKWmCj=='
   65  step1 (ROT13)                       47  '112V2h5IGRvIGVsZXBoYW50cyBoYXZlIGJpZyBlYXJzPw=='
   66  step1 (ROT13)                       46  '12I2u5VTEiVTIfMKObLJ50plObLKMyVTWcMlOyLKWmCj=='
   67  step1 (ROT13)                       45  '2V2h5IGRvIGVsZXBoYW50cyBoYXZlIGJpZyBlYXJzPw=='
   68  step2 (base64)                      31  'Why do elephants have big ears?'

Layers peeled: 68
Peel order (outermost first)  : 3 1 3 3 1 2 2 3 1 1 2 2 3 1 2 3 2 2 2 3 3 3 3 3 3 3 2 1 1 3 2 2 1 3 3 2 2 1 1 3 2 1 2 1 1 3 1 2 1 2 3 3 2 3 2 2 3 2 2 1 1 3 1 1 1 1 1 2
Encryption rounds (count)     : 67
Forward step sequence (random rounds, in applied order): 1 1 1 1 1 3 1 1 2 2 3 2 2 3 2 3 3 2 1 2 1 3 1 1 2 1 2 3 1 1 2 2 3 3 1 2 2 3 1 1 2 3 3 3 3 3 3 3 2 2 2 3 2 1 3 2 2 1 1 3 2 2 1 3 3 1 3
Step usage in rounds: step1=22 step2=22 step3=23

Recovered plaintext:
Why do elephants have big ears?
```
