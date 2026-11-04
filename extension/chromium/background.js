const NATIVE_HOST = "com.isitsafe.origin";

function runtime() {
  return globalThis.browser?.runtime ?? globalThis.chrome?.runtime;
}

function downloadsApi() {
  return globalThis.browser?.downloads ?? globalThis.chrome?.downloads;
}

function sendOrigin(item) {
  if (!item.filename || !item.url) {
    return;
  }
  const payload = {
    schema_version: 1,
    download_id: String(item.id),
    source_url: item.url,
    final_url: item.finalUrl || null,
    referrer: item.referrer || null,
    final_path: item.filename,
    timestamp: new Date(item.startTime || Date.now()).toISOString(),
    expected_size: Number.isFinite(item.totalBytes) ? item.totalBytes : null,
    browser_danger: item.danger || null
  };
  let port;
  try {
    port = runtime().connectNative(NATIVE_HOST);
  } catch (error) {
    console.error("IsItSafe native host is unavailable", error);
    return;
  }
  port.onMessage.addListener((response) => {
    if (!response?.ok) {
      console.error("IsItSafe rejected origin metadata", response?.message);
    }
    port.disconnect();
  });
  port.onDisconnect.addListener(() => {
    const error = runtime().lastError;
    if (error) {
      console.error("IsItSafe native messaging failed", error.message);
    }
  });
  port.postMessage(payload);
}

downloadsApi().onChanged.addListener((delta) => {
  if (delta.state?.current === "complete" || delta.filename?.current) {
    downloadsApi().search({ id: delta.id }, (items) => {
      if (items?.[0]) {
        sendOrigin(items[0]);
      }
    });
  }
});

