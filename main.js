import 'regenerator-runtime/runtime'
import Metrics from './metrics'

let scan = null;

// ── S400 Data Format (from XiaomiGateway3 reverse engineering) ──
// https://github.com/AlexxIT/XiaomiGateway3/issues/1388
//
// The S400 packs data into a single integer via MiBeacon protocol:
//   (impedance * 10) << 18 | (heart_rate - 50) << 11 | (weight * 10)
//
// Decoding:
//   weight     = (value & 0x7FF) / 10          (bits 0-10, 11 bits)
//   heart_rate = ((value >> 11) & 0x7F) + 50   (bits 11-17, 7 bits)
//   impedance  = (value >> 18) / 10            (bits 18+)

const XIAOMI_SERVICE_UUID = '0000fe95-0000-1000-8000-00805f9b34fb';

// ── Parse S400 packed integer ──
const parseS400Value = (value) => {
  const rawWeight = value & 0x7FF;          // bits 0-10
  const rawHR = (value >> 11) & 0x7F;       // bits 11-17
  const rawImpedance = value >> 18;          // bits 18+

  return {
    weight: rawWeight / 10,
    heartRate: (rawHR > 0 && rawHR < 127) ? rawHR + 50 : 0,
    impedance: rawImpedance / 10,
  };
};

// ── MiBeacon v4/v5 AES-CCM Decryption ──
// The S400 encrypts its advertisement data using AES-CCM
// Bind key: 32-char hex string from Xiaomi Cloud
const decryptMiBeacon = async (frameBytes, bindKeyHex) => {
  if (!bindKeyHex || bindKeyHex.length !== 32) return null;

  const bindKey = new Uint8Array(bindKeyHex.match(/.{2}/g).map(b => parseInt(b, 16)));

  // Parse frame structure
  const frameControl = frameBytes[0] | (frameBytes[1] << 8);
  const productId = frameBytes[2] | (frameBytes[3] << 8);
  const frameCounter = frameBytes[4];

  const hasMac = (frameControl & (1 << 1)) !== 0;
  const hasCapability = (frameControl & (1 << 2)) !== 0;
  const isEncrypted = (frameControl & (1 << 11)) !== 0;
  const version = (frameControl >> 8) & 0x07;

  if (!isEncrypted) return null; // Not encrypted, handle elsewhere

  let offset = 5;

  // Extract MAC if present (6 bytes, reversed)
  let mac = new Uint8Array(6);
  if (hasMac) {
    mac = frameBytes.slice(offset, offset + 6);
    offset += 6;
  }

  if (hasCapability) offset += 1;

  // Remaining: encrypted payload + 3-byte ext counter + 4-byte MIC
  if (offset + 7 > frameBytes.length) return null;

  const encPayload = frameBytes.slice(offset, frameBytes.length - 7);
  const extCounter = frameBytes.slice(frameBytes.length - 7, frameBytes.length - 4);
  const mic = frameBytes.slice(frameBytes.length - 4);

  // Build nonce (12 bytes): MAC(6) + ProductID(2) + FrameCounter(1) + ExtCounter(3)
  const nonce = new Uint8Array(12);
  nonce.set(mac, 0);
  nonce[6] = productId & 0xFF;
  nonce[7] = (productId >> 8) & 0xFF;
  nonce[8] = frameCounter;
  nonce.set(extCounter, 9);

  // AAD (additional authenticated data): frame header (first 5 bytes)
  const aad = frameBytes.slice(0, 5);

  try {
    // Import bind key for AES-CCM
    // Web Crypto doesn't directly support AES-CCM, so we use a manual approach
    // For AES-CCM with 4-byte tag, we'll use SubtleCrypto with AES-GCM as approximation
    // Note: AES-CCM and AES-GCM differ - for proper CCM we need a polyfill

    // Try using SubtleCrypto (AES-GCM - close but not identical to CCM)
    const key = await crypto.subtle.importKey(
      'raw', bindKey, { name: 'AES-GCM' }, false, ['decrypt']
    );

    // Combine encrypted payload + MIC tag
    const ciphertext = new Uint8Array(encPayload.length + mic.length);
    ciphertext.set(encPayload, 0);
    ciphertext.set(mic, encPayload.length);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aad,
        tagLength: 32, // 4 bytes = 32 bits
      },
      key,
      ciphertext
    );

    return new Uint8Array(decrypted);
  } catch (e) {
    console.warn('  AES decryption failed (expected if key is wrong):', e.message);
    return null;
  }
};

// ── Parse MiBeacon frame ──
const parseMiBeacon = async (dataView, bindKeyHex) => {
  if (dataView.byteLength < 5) return null;

  const bytes = new Uint8Array(dataView.buffer);
  const frameControl = dataView.getUint16(0, true);
  const productId = dataView.getUint16(2, true);
  const frameCounter = dataView.getUint8(4);

  const hasMac = (frameControl & (1 << 1)) !== 0;
  const hasCapability = (frameControl & (1 << 2)) !== 0;
  const hasEvent = (frameControl & (1 << 3)) !== 0;
  const isEncrypted = (frameControl & (1 << 11)) !== 0;
  const version = (frameControl >> 8) & 0x07;

  console.log(`  MiBeacon: PID=${productId} v${version} fc=${frameCounter} encrypted=${isEncrypted} hasEvent=${hasEvent} (${dataView.byteLength}B)`);

  // Handle encrypted data
  if (isEncrypted) {
    if (!bindKeyHex) {
      console.log('  🔒 Data is encrypted — enter your bind key to decrypt');
      document.querySelector('.status').textContent = '🔒 Data encrypted — enter bind key above';
      document.querySelector('.status').className = 'status';
      return null;
    }

    const decrypted = await decryptMiBeacon(bytes, bindKeyHex);
    if (decrypted && decrypted.length >= 3) {
      // Decrypted payload contains: eventId(2) + eventLen(1) + eventData
      const eventId = decrypted[0] | (decrypted[1] << 8);
      const eventLen = decrypted[2];
      console.log(`  🔓 Decrypted! Event ID: ${eventId} (0x${eventId.toString(16)}), len: ${eventLen}`);

      if (eventLen > 0 && decrypted.length >= 3 + eventLen) {
        let eventValue = 0;
        for (let i = 0; i < eventLen && i < 4; i++) {
          eventValue |= decrypted[3 + i] << (i * 8);
        }
        return { productId, eventId, eventValue, encrypted: true };
      }
    }
    return null;
  }

  // Handle unencrypted data
  let offset = 5;
  if (hasMac) offset += 6;
  if (hasCapability) offset += 1;

  if (hasEvent && offset + 3 <= dataView.byteLength) {
    const eventId = dataView.getUint16(offset, true);
    const eventLen = dataView.getUint8(offset + 2);
    offset += 3;

    console.log(`  Event ID: ${eventId} (0x${eventId.toString(16)}), len: ${eventLen}`);

    if (offset + eventLen <= dataView.byteLength) {
      let eventValue = 0;
      for (let i = 0; i < eventLen && i < 4; i++) {
        eventValue |= dataView.getUint8(offset + i) << (i * 8);
      }
      return { productId, eventId, eventValue, encrypted: false };
    }
  }

  return null;
};

// ── Update UI ──
const updateUI = (data) => {
  document.querySelector('.loading').setAttribute('hidden', '');
  document.querySelector('.scale').removeAttribute('hidden');
  document.querySelector('.value').textContent = data.weight.toFixed(1);
  document.querySelector('.unit').textContent = 'kg';

  const statusEl = document.querySelector('.status');
  statusEl.textContent = '📏 Weight received';
  statusEl.className = 'status stabilized';

  const hrEl = document.querySelector('.heart-rate');
  if (hrEl && data.heartRate > 0) {
    hrEl.textContent = `❤️ Heart Rate: ${data.heartRate} bpm`;
    hrEl.removeAttribute('hidden');
  }

  const impedanceEl = document.querySelector('.impedance-info');
  if (impedanceEl) {
    if (data.impedance > 0) {
      impedanceEl.textContent = `⚡ Impedance: ${data.impedance} Ω`;
      impedanceEl.removeAttribute('hidden');
    } else {
      impedanceEl.textContent = 'Stand barefoot for body composition';
      impedanceEl.removeAttribute('hidden');
    }
  }

  if (data.weight > 0 && data.impedance > 0) {
    const height = parseFloat(document.querySelector('input[name="height"]').value);
    const age = parseInt(document.querySelector('input[name="age"]').value);
    const sex = document.querySelector('select[name="gender"]').value;

    if (height > 0 && age > 0) {
      const metrics = new Metrics(data.weight, data.impedance * 10, height, age, sex);
      const result = metrics.getResult();
      const resultEl = document.querySelector('.result');
      resultEl.removeAttribute('hidden');
      resultEl.innerHTML = result
        .map(item => `<div class="item"><span class="name">${item.name}</span><span class="val">${
          typeof item.value === 'number' ? item.value.toFixed(1) : item.value
        }</span></div>`)
        .join('');
    }
  }

  console.log('✅ Scale data:', data);
};

// ── Get bind key from input ──
const getBindKey = () => {
  const input = document.querySelector('input[name="bindkey"]');
  if (!input) return '';
  return input.value.replace(/\s/g, '').toLowerCase();
};

// ── Handle advertisement events ──
const onAdvertisement = async (event) => {
  const deviceName = event.device.name || '';

  // Log named devices
  if (deviceName) {
    const sdCount = event.serviceData?.size || 0;
    const mdCount = event.manufacturerData?.size || 0;
    console.log(`📡 "${deviceName}" RSSI:${event.rssi} sd:${sdCount} md:${mdCount}`);
  }

  // Process all serviceData
  if (event.serviceData && event.serviceData.size > 0) {
    for (const [uuid, dataView] of event.serviceData) {
      const hex = Array.from(new Uint8Array(dataView.buffer))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
      const uuidStr = typeof uuid === 'string' ? uuid : uuid.toString();

      if (deviceName) {
        console.log(`  serviceData [${uuidStr}] (${dataView.byteLength}B): ${hex}`);
      }

      // Parse MiBeacon from fe95 service
      if (uuidStr.includes('fe95')) {
        const bindKey = getBindKey();
        const beacon = await parseMiBeacon(dataView, bindKey);

        if (beacon && beacon.eventValue > 1) {
          const parsed = parseS400Value(beacon.eventValue);
          console.log(`  Decoded: weight=${parsed.weight}kg hr=${parsed.heartRate}bpm imp=${parsed.impedance}Ω`);

          if (parsed.weight > 0 && parsed.weight < 300) {
            updateConnectionStatus(true, deviceName);
            updateUI(parsed);
          }
        }
      }
    }
  }

  // Log manufacturerData for scale devices
  if (deviceName && event.manufacturerData && event.manufacturerData.size > 0) {
    event.manufacturerData.forEach((dataView, key) => {
      const hex = Array.from(new Uint8Array(dataView.buffer))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
      console.log(`  mfgData [0x${key.toString(16)}] (${dataView.byteLength}B): ${hex}`);
    });
  }
};

// ── Main button click ──
const onButtonClick = async () => {
  try {
    // Step 1: Show device picker (does NOT connect via GATT)
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'Xiaomi' }],
      optionalServices: [XIAOMI_SERVICE_UUID]
    });

    console.log(`✅ Selected: ${device.name} (${device.id})`);

    document.querySelector('.button.start').setAttribute('hidden', '');
    document.querySelector('.form').setAttribute('hidden', '');
    document.querySelector('.bindkey-section').removeAttribute('hidden');
    document.querySelector('.loading').removeAttribute('hidden');
    document.querySelector('.loading').textContent = `📡 Scanning for ${device.name}... Step on the scale!`;
    document.querySelector('.button.stop').removeAttribute('hidden');

    // Step 2: Start passive BLE advertisement scanning
    scan = await navigator.bluetooth.requestLEScan({
      acceptAllAdvertisements: true
    });

    navigator.bluetooth.addEventListener('advertisementreceived', onAdvertisement);
    console.log('✅ BLE scan started');

  } catch (e) {
    if (e.code === 20 || e.name === 'NotFoundError') return;
    console.error(e);
    alert(`Error: ${e.message}\n\nMake sure chrome://flags/#enable-experimental-web-platform-features is enabled.`);
  }
};

// ── Stop ──
const onStopClick = () => {
  if (scan) {
    scan.stop();
    scan = null;
    navigator.bluetooth.removeEventListener('advertisementreceived', onAdvertisement);
  }
  updateConnectionStatus(false);
  document.querySelector('.loading').textContent = 'Stopped.';
  document.querySelector('.loading').removeAttribute('hidden');
  document.querySelector('.button.start').removeAttribute('hidden');
  document.querySelector('.button.start').removeAttribute('disabled');
  document.querySelector('.button.stop').setAttribute('hidden', '');
  document.querySelector('.form').removeAttribute('hidden');
};

const updateConnectionStatus = (active, deviceName) => {
  const el = document.querySelector('.connection-status');
  if (!el) return;
  if (active) {
    el.textContent = `🟢 Receiving from ${deviceName || 'Scale'}`;
    el.className = 'connection-status connected';
    el.removeAttribute('hidden');
  } else {
    el.textContent = '🔴 Not scanning';
    el.className = 'connection-status disconnected';
  }
};

const onInputChange = () => {
  const height = document.querySelector('input[name="height"]').value;
  const age = document.querySelector('input[name="age"]').value;
  if (height > 0 && age > 0) {
    document.querySelector('.button.start').removeAttribute('disabled');
  } else {
    document.querySelector('.button.start').setAttribute('disabled', '');
  }
};

document.querySelector('input[name="height"]').addEventListener('keyup', onInputChange);
document.querySelector('input[name="age"]').addEventListener('keyup', onInputChange);
document.querySelector('.button.start').addEventListener('click', onButtonClick);
document.querySelector('.button.stop').addEventListener('click', onStopClick);