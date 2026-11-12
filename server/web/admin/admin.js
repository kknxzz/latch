"use strict";
(() => {
  const byID = id => document.getElementById(id);
  let csrf = "";
  let codeTimer;
  function notice(text) { byID("notice").textContent = text; }
  function clearCode() { clearTimeout(codeTimer); byID("code").textContent = ""; byID("code-expiry").textContent = ""; byID("code-panel").hidden = true; }
  function signedOut() { csrf = ""; clearCode(); byID("dashboard").hidden = true; byID("login-panel").hidden = false; byID("devices").replaceChildren(); byID("events").replaceChildren(); }
  async function request(path, body) {
    const options = { credentials: "same-origin", cache: "no-store", headers: {} };
    if (body !== undefined) { options.method = "POST"; options.headers["Content-Type"] = "application/json"; options.headers["X-CSRF-Token"] = csrf; options.body = JSON.stringify(body); }
    const response = await fetch("/admin/api/" + path, options);
    const data = await response.json();
    if (!response.ok) { if (response.status === 401) signedOut(); throw new Error(data.error || "Request failed."); }
    return data;
  }
  function cell(row, text, className) { const td = document.createElement("td"); td.textContent = text; if (className) td.className = className; row.append(td); return td; }
  async function refresh() {
    const [status, devices, events] = await Promise.all([request("status"), request("devices"), request("events")]);
    byID("health").textContent = status.healthy ? "Healthy" : "Unavailable";
    byID("connections").textContent = status.connections; byID("rooms").textContent = status.rooms;
    byID("uptime").textContent = Math.floor(status.uptime_seconds / 60) + "m";
    byID("device-count").textContent = devices.length + " Registered"; byID("devices").replaceChildren();
    for (const device of devices) {
      const row = document.createElement("tr"); const label = cell(row, device.nickname || "Unnamed Device");
      const id = document.createElement("small"); id.textContent = device.device_id; id.title = device.fingerprint; label.append(id);
      cell(row, device.uuid, "uuid"); cell(row, device.banned ? "Removed Permanently" : device.connected ? "Connected" : "Enrolled");
      cell(row, new Date(device.enrolled_at).toLocaleString()); const action = cell(row, "");
      if (!device.banned) { const button = document.createElement("button"); button.type = "button"; button.className = "danger"; button.textContent = "Remove Permanently";
        button.addEventListener("click", async () => { if (!window.confirm("Permanently remove " + (device.nickname || device.device_id) + "? This public key cannot enroll again.")) return;
          button.disabled = true; try { await request("devices/" + encodeURIComponent(device.uuid) + "/ban", {}); notice("Device permanently removed."); await refresh(); } catch (error) { notice(error.message); button.disabled = false; } }); action.append(button); }
      byID("devices").append(row);
    }
    byID("events").replaceChildren();
    for (const event of events.slice().reverse()) { const li = document.createElement("li"); const time = document.createElement("time"); time.textContent = new Date(event.time).toLocaleTimeString();
      const text = document.createElement("span"); const description = event.kind.replaceAll("_", " "); text.textContent = description.charAt(0).toUpperCase() + description.slice(1) + (event.device_id ? " · " + event.device_id : ""); li.append(time, text); byID("events").append(li); }
  }
  async function signedIn(token) { csrf = token; byID("login-panel").hidden = true; byID("dashboard").hidden = false; await refresh(); }
  byID("login-form").addEventListener("submit", async event => { event.preventDefault(); const button = event.submitter || byID("login-form").querySelector("button[type=submit]"); button.disabled = true;
    try { const session = await request("login", { password: byID("password").value, totp: byID("totp").value }); notice(""); await signedIn(session.csrf); }
    catch (error) { notice(error.message); } finally { byID("password").value = ""; byID("totp").value = ""; button.disabled = false; } });
  byID("refresh").addEventListener("click", () => refresh().catch(error => notice(error.message)));
  byID("logout").addEventListener("click", async () => { try { await request("logout", {}); signedOut(); notice("Signed out."); } catch (error) { notice(error.message); } });
  byID("generate").addEventListener("click", async () => { const button = byID("generate"); button.disabled = true; try { const enrollment = await request("enrollment-codes", {}); clearCode();
    byID("code").textContent = enrollment.code; byID("code-expiry").textContent = "One use. Expires at " + new Date(enrollment.expires_at).toLocaleTimeString() + ", unless already used.";
    byID("code-panel").hidden = false; codeTimer = setTimeout(clearCode, Math.max(0, Date.parse(enrollment.expires_at) - Date.now())); await refresh(); } catch (error) { notice(error.message); } finally { button.disabled = false; } });
  request("session").then(session => signedIn(session.csrf)).catch(() => signedOut());
})();
