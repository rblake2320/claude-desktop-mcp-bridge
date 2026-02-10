import("@modelcontextprotocol/sdk/server/index.js")
  .then(m => console.log("SDK loaded OK", Object.keys(m)))
  .catch(e => console.error("SDK FAILED:", e.message));
