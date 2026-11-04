# IsItSafe browser extension

The extension sends completed download metadata to the locally registered `com.isitsafe.origin` Native Messaging host.

## Chromium

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable Developer mode.
3. Choose **Load unpacked** and select `extension\chromium`.
4. Copy the displayed extension ID into `origin.chrome_extension_ids`.
5. Run `isitsafe.exe install-host`.

## Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on** and select `extension\firefox\manifest.json`.
3. Use the extension ID from the manifest in `origin.firefox_extension_ids`.
4. Run `isitsafe.exe install-host`.

Firefox temporary extensions are removed when Firefox closes. Permanent installation requires signing and packaging by Mozilla.

