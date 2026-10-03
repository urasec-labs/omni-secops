# CyberChef Data Transformation Recipes

| Field | Value |
|---|---|
| `tool_id` | TOOL-CYBERCHEF |
| `source` | gchq/CyberChef @ v10.42.0 |
| `license` | Apache-2.0 |
| `recipe_dir` | `07-tooling/cyberchef/recipes/` |
| `recipe_format` | CyberChef "Save recipe" JSON (see `recipes/*.recipe.json`) |

## 1. Why recipes are archived

Two reasons, both operational:

1. **Repeatability.** "Decode this blob the way we did last quarter" is a recipe,
   not a series of GUI clicks. Recipes are diffable, reviewable, and testable.
2. **Defensive utility.** Most recipes in the archive reverse-engineer attacker
   behaviour: decode a C2 config, unpack a layered encoding, identify an
   algorithm from ciphertext structure.

## 2. Recipe catalogue

| Recipe file | Use case | Operations |
|---|---|---|
| `url-decode-chain.recipe.json` | Multi-layer URL/hex encoding | URL Decode, Decode text (Base64), From Hex |
| `jwt-decode.recipe.json` | Read a JWT header/payload without a key | nothing - just eyeball |
| `pkcs7-asn1.parse.recipe.json` | Read certificate structure | Parse X.509 certificate, ASN.1 dump |
| `ransomware-note-extract.recipe.json` | Pull config from a ransom note | Find (Regex), Match offset, Drop bytes |
| `dns-exfil-extract.recipe.json` | Reassemble hex data from subdomains | Regex groups, Concat, From Hex |
| `cobalt-strike-config.recipe.json` | Decode an encoded beacon config | XOR, From Hex, Find |
| `powershell-obfuscation-unfold.recipe.json` | Normalise `-eNxx` encoded commands | Charcode, From Decimal |

## 3. Using a recipe

```bash
# open the CyberChef web app, Menu > Load recipe, paste the JSON
# or run headless against a file
node cyberchef_cli.js -r 07-tooling/cyberchef/recipes/url-decode-chain.recipe.json \
                      -i input.bin -o output.txt
```

## 4. Authoring rules

1. Every operation in a recipe must be from the CyberChef operation catalogue
   (check the operation count in the "Save recipe" dialog).
2. Recipes must be **idempotent or explicitly single-pass**; document which.
3. No operation that reaches the network (`Fetch URL`, `Scan for IP addresses`
   is fine - it is local).
4. Include `description`, `author`, `created` in the recipe JSON.
5. Test the recipe against a known input and store both under
   `07-tooling/cyberchef/recipes/` with the expected output in the commit
   message or the recipe `notes` field.

## 5. Cautions

* Decoding untrusted data can produce huge output - set an operation limit.
* `Detect magic numbers` and `Identify` are heuristic; confirm before reporting.
* A recipe that "works" in the GUI may fail headless if it depends on a
  randomly chosen key; pin the key in the recipe arguments.
