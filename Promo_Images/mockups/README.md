# Promo Screenshot Mockups

This folder contains high-fidelity HTML mockups for all ScamShield store/website screenshots, designed to match the existing promo images in `Promo_Images/` (same dark slate theme, emerald green `#10b981` accents, same typography and card styling).

## Files

| Mockup | Screenshot it replaces | Purpose |
|---|---|---|
| `screenshot-1-scan.html` | `screenshot-1-scan-1280x800.png` | Scan landing page |
| `screenshot-2-history.html` | `screenshot-2-history-1280x800.png` | Security timeline |
| `screenshot-3-privacy.html` | `screenshot-3-privacy-1280x800.png` | Privacy explainer |
| `screenshot-ai-analysis-summary.html` | `screenshot-ai-analysis-summary.png` | AI analysis summary card |
| `screenshot-ai-indicators.html` | `screenshot-ai-indicators.png` | AI finding indicators |
| `screenshot-block-page.html` | `screenshot-block-page.png` | Full-tab block page |
| `screenshot-critical-rule-findings.html` | `screenshot-critical-rule-findings.png` | Critical rule findings |
| `screenshot-form-submit-warning.html` | `screenshot-form-submit-warning.png` | Form submit interstitial |
| `screenshot-risk-factor-cards.html` | `screenshot-risk-factor-cards.png` | Risk factor cards |
| `screenshot-rule-evidence.html` | `screenshot-rule-evidence.png` | Rule evidence list |

## Design system (matches existing promo images)

- **Background:** `linear-gradient(135deg, #0f172a 0%, #020617 100%)` with subtle radial glows
- **Primary accent:** Emerald green `#10b981` (buttons, badges, shield)
- **Critical accent:** Red `#ef4444` (block page, warnings)
- **Cards:** Dark slate `#0f172a` with `1px solid rgba(255,255,255,0.06)` border
- **Typography:** System sans-serif, white headings, slate-400 body
- **Phone mockup:** 430×760px, `#020617`, `44px` border radius, subtle inner glow

## How to render to PNG

### Option A — Chrome / Edge headless (recommended, exact pixel output)

Open PowerShell in `Promo_Images\mockups\` and run:

```powershell
$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$out = ".."
foreach ($file in Get-ChildItem *.html) {
  $name = $file.BaseName
  & $chrome --headless --disable-gpu --screenshot --window-size=1280,800 --virtual-time-budget=2000 --outfile="$out\$name.png" "file:///$($file.FullName)"
}
```

This produces PNGs matching the mockup filenames (e.g. `screenshot-1-scan.png`). Rename them to match your store asset names (e.g. `screenshot-1-scan-1280x800.png`) and copy into `Promo_Images/`.

### Option B — Browser + screenshot extension

1. Open each `.html` file in Chrome or Edge.
2. Set zoom to 100%, window to 1280×800 (or full screen for the phone mockup).
3. Use a full-page screenshot extension (e.g. GoFullPage) or DevTools > Command Menu > "Capture full size screenshot".
4. Save as PNG and place in `Promo_Images/`.

## Notes

- The HTML files are self-contained (no external assets, no network requests) so they render identically offline.
- The phone mockup is sized 430×760 to match a mobile viewport inside a 1280×800 canvas — consistent with your existing promo screenshot dimensions.
- If you need different dimensions, edit the `--window-size` in the headless command or adjust the `.scene`/`.phone` CSS in each file.
