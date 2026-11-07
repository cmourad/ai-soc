const { app, BrowserWindow, shell } = require("electron");
const fs = require("node:fs");
const path = require("node:path");

const DEV_URL = process.env.AISOC_UI_URL ?? "http://127.0.0.1:5319";
// Same-origin: the backend serves the built UI, so the packaged app needs no CORS.
const PROD_URL = process.env.AISOC_API_URL ?? "http://127.0.0.1:4319";
const isDev = process.env.AISOC_DEV === "1";
const appUrl = new URL(isDev ? DEV_URL : PROD_URL);
const bootstrapPath = process.env.AISOC_BOOTSTRAP_FILE ?? "/var/lib/aisoc-desktop/bootstrap.key";

function safeExternal(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1600,
    height: 980,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: "#1e1e1e",
    autoHideMenuBar: true,
    title: "AI SOC Console",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });

  // Inject the deploy-provisioned credential only into the local bootstrap
  // request. It is never exposed through contextBridge, localStorage, or logs.
  if (!isDev) {
    let bootstrap = "";
    try {
      bootstrap = fs.readFileSync(bootstrapPath, "utf8").trim();
    } catch {
      // The API fails closed and the UI stays disconnected until provisioning
      // is repaired. Never invent a production fallback credential.
    }
    window.webContents.session.webRequest.onBeforeSendHeaders(
      { urls: [`${appUrl.origin}/api/session`] },
      (details, callback) => {
        const requestHeaders = { ...details.requestHeaders };
        if (bootstrap) requestHeaders["x-aisoc-bootstrap"] = bootstrap;
        callback({ requestHeaders });
      },
    );
  }

  if (isDev) {
    window.loadURL(DEV_URL);
  } else {
    window.loadURL(PROD_URL);
  }

  // Anything that wants a new window opens in the real browser instead.
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (safeExternal(url)) void shell.openExternal(url);
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, url) => {
    try {
      if (new URL(url).origin === appUrl.origin) return;
    } catch {
      // Invalid navigation is always denied.
    }
    event.preventDefault();
  });
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
