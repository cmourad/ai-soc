const { contextBridge } = require("electron");

// The renderer talks to the backend over HTTP/WS, so it needs no privileged
// bridge — this only exposes enough for the UI to know it is running desktop-side.
contextBridge.exposeInMainWorld("aisoc", {
  desktop: true,
  platform: process.platform,
});
