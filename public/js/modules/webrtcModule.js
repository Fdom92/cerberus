const STUN_SERVER = "stun:stun.l.google.com:19302";
const IP_ECHO_URL = "https://api.ipify.org?format=json";
const GATHER_TIMEOUT_MS = 5000;
const FETCH_TIMEOUT_MS = 5000;

function extractCandidateInfo(candidate) {
  const address =
    candidate.address ||
    (candidate.candidate.match(/(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f-]+\.local/i) || [])[0] ||
    null;
  let type = candidate.type || null;
  if (!type) {
    if (candidate.candidate.includes("typ host")) type = "host";
    else if (candidate.candidate.includes("typ srflx")) type = "srflx";
  }
  return { address, type };
}

async function gatherIceCandidates() {
  const localIps = new Set();
  const stunIps = new Set();
  let mdnsSeen = false;

  const pc = new RTCPeerConnection({ iceServers: [{ urls: STUN_SERVER }] });
  pc.createDataChannel("leak-test");

  await new Promise((resolve) => {
    const timer = setTimeout(resolve, GATHER_TIMEOUT_MS);
    pc.onicecandidate = (e) => {
      if (!e.candidate) {
        clearTimeout(timer);
        resolve();
        return;
      }
      const { address, type } = extractCandidateInfo(e.candidate);
      if (!address) return;
      if (address.endsWith(".local")) {
        mdnsSeen = true;
        return;
      }
      if (type === "host") localIps.add(address);
      if (type === "srflx") stunIps.add(address);
    };
    pc
      .createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => {
        clearTimeout(timer);
        resolve();
      });
  });

  pc.close();
  return { localIps: [...localIps], stunIps: [...stunIps], mdnsSeen };
}

async function fetchPublicIp() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(IP_ECHO_URL, { signal: controller.signal });
    const data = await res.json();
    return data.ip || null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export const WEBRTC_FLAG_LABELS = {
  local_ip_exposed: "Tu navegador expone tu IP local de red a cualquier web que use WebRTC",
  mdns_protected: "Buena señal: tu navegador oculta la IP local real (usa un alias mDNS aleatorio)",
  public_ip_leak: "Fuga detectada: el STUN ve una IP pública distinta a la de tu conexión HTTPS normal — posible fuga de VPN",
  no_candidates: "No se obtuvo ningún candidato ICE (STUN bloqueado o red muy restrictiva) — buena señal de privacidad, pero no se pudo diagnosticar una fuga",
  ip_echo_failed: "No se pudo contactar el servicio de IP pública para comparar",
};

export async function checkWebRtcLeak() {
  const [{ localIps, stunIps, mdnsSeen }, publicIpViaHttps] = await Promise.all([
    gatherIceCandidates(),
    fetchPublicIp(),
  ]);

  const flags = [];
  if (localIps.length > 0) flags.push("local_ip_exposed");
  if (mdnsSeen) flags.push("mdns_protected");
  if (!publicIpViaHttps) flags.push("ip_echo_failed");
  if (localIps.length === 0 && stunIps.length === 0) flags.push("no_candidates");

  let leakDetected = null;
  if (publicIpViaHttps && stunIps.length > 0) {
    leakDetected = !stunIps.includes(publicIpViaHttps);
    if (leakDetected) flags.push("public_ip_leak");
  }

  const verdict = leakDetected === true ? "dangerous" : leakDetected === false ? "safe" : "unknown";

  return {
    type: "webrtc",
    localIps,
    stunIps,
    mdnsSeen,
    publicIpViaHttps,
    leakDetected,
    flags,
    verdict,
    timestamp: Date.now(),
  };
}
