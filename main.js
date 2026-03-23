import 'regenerator-runtime/runtime'
import Metrics from './metrics'

let scan = null;

// ── S400 Configuration ──
// BLE KEY from Xiaomi Cloud Tokens Extractor
const BIND_KEY_HEX = 'fe124135b623f23c202f4dae69d41836';
const BIND_KEY = hexToBytes(BIND_KEY_HEX);

// Device MAC: 34:FA:1C:17:A9:99
// In BLE advertisement byte order (reversed): 99 A9 17 1C FA 34
const DEVICE_MAC = new Uint8Array([0x99, 0xA9, 0x17, 0x1C, 0xFA, 0x34]);
// Forward order: 34 FA 1C 17 A9 99
const DEVICE_MAC_FORWARD = new Uint8Array([0x34, 0xFA, 0x1C, 0x17, 0xA9, 0x99]);

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// ── S400 Data Format (XiaomiGateway3 reverse engineering) ──
// (impedance * 10) << 18 | (heart_rate - 50) << 11 | (weight * 10)
const parseS400Value = (value) => {
  const rawWeight = value & 0x7FF;          // bits 0-10 (11 bits)
  const rawHR = (value >> 11) & 0x7F;       // bits 11-17 (7 bits)
  const rawImpedance = value >> 18;          // bits 18+

  return {
    weight: rawWeight !== 0 ? rawWeight / 10 : 0,
    heartRate: (rawHR > 0 && rawHR < 127) ? rawHR + 50 : 0,
    impedance: rawImpedance !== 0 ? rawImpedance / 10 : 0,
  };
};

// ── MiBeacon v5 Frame Parser ──
// Frame Control (2 bytes, LE):
//   bit 0: factory_new
//   bit 1: connected
//   bit 2: central
//   bit 3: encrypted
//   bit 4: mac_include
//   bit 5: capability_include
//   bit 6-7: object_include (0=none, 1=has object)
//   bit 8-11: mesh
//   bit 12-14: version
//   bit 15: reserved
const parseMiBeacon = (dataView) => {
  if (dataView.byteLength < 5) return null;

  const frameControl = dataView.getUint16(0, true);
  const productId = dataView.getUint16(2, true);
  const frameCounter = dataView.getUint8(4);

  const isEncrypted = (frameControl & (1 << 3)) !== 0;
  const hasMac = (frameControl & (1 << 4)) !== 0;
  const hasCapability = (frameControl & (1 << 5)) !== 0;
  const objectInclude = (frameControl >> 6) & 0x03;
  const hasObject = objectInclude !== 0;
  const version = (frameControl >> 12) & 0x07;

  let offset = 5;
  let mac = null;

  // Extract MAC if present (6 bytes)
  if (hasMac) {
    mac = new Uint8Array(dataView.buffer, dataView.byteOffset + offset, 6);
    offset += 6;
  }

  // Skip capability (1 byte)
  if (hasCapability) offset += 1;

  console.log(`  MiBeacon v${version}: PID=0x${productId.toString(16)} fc=${frameCounter} encrypted=${isEncrypted} hasObject=${hasObject} hasMac=${hasMac} offset=${offset} len=${dataView.byteLength}`);

  return {
    frameControl, productId, frameCounter, version,
    isEncrypted, hasMac, hasCapability, hasObject,
    mac, offset
  };
};
// ── AES-CCM Decryption — exact HA xiaomi_ble implementation ──
// From: https://github.com/Bluetooth-Devices/xiaomi-ble/blob/main/src/xiaomi_ble/parser.py
//
// nonce = xiaomi_mac[::-1] + data[2:5] + data[-7:-4]  (12 bytes)
// encrypted_payload = data[i:-7]   (where i = offset after header)
// mic = data[-4:]
// AAD = b"\x11"
//
// xiaomi_mac in HA is stored in FORWARD order (34:FA:1C:17:A9:99)
// [::-1] reverses it to BLE order (99:A9:17:1C:FA:34)

async function decryptMiBeaconV4V5(fullData, headerOffset) {
  // fullData = entire raw serviceData bytes
  // headerOffset = byte offset where encrypted payload starts (after FC+PID+FrameCnt+[MAC]+[Cap])

  if (fullData.length < headerOffset + 7) {
    console.log('  Not enough data for decryption');
    return null;
  }

  // Exact HA construction:
  // nonce = xiaomi_mac[::-1] + data[2:5] + data[-7:-4]
  // xiaomi_mac is stored in forward order in HA, [::-1] reverses to BLE order
  // DEVICE_MAC is already in BLE order: [99, A9, 17, 1C, FA, 34]
  const nonce = new Uint8Array(12);
  nonce.set(DEVICE_MAC, 0);                                          // MAC BLE order (6 bytes)
  nonce.set(fullData.slice(2, 5), 6);                                // data[2:5] = PID(2) + FrameCnt(1) raw bytes
  nonce.set(fullData.slice(fullData.length - 7, fullData.length - 4), 9); // data[-7:-4] = ext counter (3 bytes)

  const encryptedPayload = fullData.slice(headerOffset, fullData.length - 7);
  const mic = fullData.slice(fullData.length - 4);

  const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const ctHex = Array.from(encryptedPayload).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const micHex = Array.from(mic).map(b => b.toString(16).padStart(2, '0')).join(' ');

  console.log(`  Nonce (12B): ${nonceHex}`);
  console.log(`  Encrypted (${encryptedPayload.length}B): ${ctHex}`);
  console.log(`  MIC: ${micHex}`);

  // AES-CCM decrypt using AES-CTR (CTR is the decryption part of CCM)
  // Nonce = 12 bytes → Q = 15 - 12 = 3, flags = Q - 1 = 2
  const key = await crypto.subtle.importKey(
    'raw', BIND_KEY, { name: 'AES-CTR' }, false, ['encrypt']
  );

  // Counter block A1: flags(1) || nonce(12) || counter(3) = 16 bytes
  const counterBlock = new Uint8Array(16);
  counterBlock[0] = 2; // flags = Q - 1 = 2
  counterBlock.set(nonce, 1); // nonce at bytes 1-12
  counterBlock[15] = 1; // counter = 1 (big-endian, 3-byte counter)

  const decrypted = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter: counterBlock, length: 24 }, // 24 bits = 3 byte counter
    key,
    encryptedPayload
  );

  const decryptedBytes = new Uint8Array(decrypted);
  const decHex = Array.from(decryptedBytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
  console.log(`  Decrypted (${decryptedBytes.length}B): ${decHex}`);

  // Validate: first 2 bytes should be event ID 0x03FE for S400
  if (decryptedBytes.length >= 2) {
    const eventId = decryptedBytes[0] | (decryptedBytes[1] << 8);
    console.log(`  Event ID: 0x${eventId.toString(16)} ${eventId === 0x03FE ? '✅' : '❌'}`);
  }

  return decryptedBytes;
}

// ── Parse decrypted MiBeacon object ──
// Format: objectId(2, LE) + length(1) + data(N)
// For S400: data = PIID(1) + packedValue(4) + ...
function parseDecryptedObject(data) {
  if (data.length < 7) return null;

  const objectId = data[0] | (data[1] << 8);
  const dataLen = data[2];
  const piid = data[3]; // Property Instance ID (usually 0x01)

  // S400 packed value is a uint32LE starting at byte 4
  // (after objectId(2) + len(1) + piid(1))
  let packedValue = 0;
  for (let i = 0; i < 4 && (4 + i) < data.length; i++) {
    packedValue |= data[4 + i] << (i * 8);
  }
  // Ensure unsigned
  packedValue = packedValue >>> 0;

  console.log(`  Object: id=0x${objectId.toString(16)} len=${dataLen} piid=${piid} packed=0x${packedValue.toString(16)} (${packedValue})`);

  return { objectId, dataLen, piid, packedValue };
}

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
      impedanceEl.textContent = 'Stand barefoot on electrodes for body composition';
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

// ── Handle advertisement events ──
const onAdvertisement = async (event) => {
  const deviceName = event.device.name || '';

  if (event.serviceData && event.serviceData.size > 0) {
    event.serviceData.forEach(async (dataView, uuid) => {
      const hex = Array.from(new Uint8Array(dataView.buffer, dataView.byteOffset, dataView.byteLength))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');

      const uuidStr = typeof uuid === 'string' ? uuid : uuid.toString();
      const isMiBeacon = uuidStr.includes('fe95');

      if (isMiBeacon) {
        console.log(`📡 "${deviceName}" RSSI:${event.rssi} fe95 (${dataView.byteLength}B): ${hex}`);

        const beacon = parseMiBeacon(dataView);
        if (!beacon) return;

        if (beacon.isEncrypted && beacon.hasObject) {
          // ENCRYPTED event data — decrypt with exact HA implementation
          console.log('  🔐 Encrypted event detected — decrypting...');

          // Pass the FULL raw serviceData bytes (HA uses raw byte offsets like data[2:5])
          const fullData = new Uint8Array(dataView.buffer, dataView.byteOffset, dataView.byteLength);

          try {
            const decrypted = await decryptMiBeaconV4V5(fullData, beacon.offset);

            if (decrypted) {
              const obj = parseDecryptedObject(decrypted);
              if (obj && obj.packedValue > 0) {
                // S400 Body Composition Object ID is 0x6e16 (28182).
                // Or we just check if it parsed a valid packed value.
                const parsed = parseS400Value(obj.packedValue);
                console.log(`  🏋️ weight=${parsed.weight}kg hr=${parsed.heartRate}bpm impedance=${parsed.impedance}Ω`);
                if (parsed.weight > 0 && parsed.weight < 300) {
                  updateConnectionStatus(true, deviceName);
                  updateUI(parsed);
                }
              }
            }
          } catch (e) {
            console.warn('  Decryption error:', e.message);
          }
        } else if (!beacon.isEncrypted && beacon.hasObject) {
          // UNENCRYPTED event data
          console.log('  📦 Unencrypted event data');
          if (beacon.offset + 3 <= dataView.byteLength) {
            const eventData = new Uint8Array(
              dataView.buffer, dataView.byteOffset + beacon.offset,
              dataView.byteLength - beacon.offset
            );
            const obj = parseDecryptedObject(eventData);
            if (obj && obj.eventValue > 1) {
              const parsed = parseS400Value(obj.eventValue);
              console.log(`  🏋️ weight=${parsed.weight}kg hr=${parsed.heartRate}bpm impedance=${parsed.impedance}Ω`);
              if (parsed.weight > 0 && parsed.weight < 300) {
                updateConnectionStatus(true, deviceName);
                updateUI(parsed);
              }
            }
          }
        } else {
          // Idle beacon (no object data)
          console.log('  💤 Idle beacon (no measurement data)');
        }
      }
    });
  }

  // Also log manufacturer data from the scale
  if (deviceName.toLowerCase().includes('xiaomi') && event.manufacturerData && event.manufacturerData.size > 0) {
    event.manufacturerData.forEach((dataView, key) => {
      const hex = Array.from(new Uint8Array(dataView.buffer, dataView.byteOffset, dataView.byteLength))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
      console.log(`📡 "${deviceName}" mfgData [0x${key.toString(16)}] (${dataView.byteLength}B): ${hex}`);
    });
  }
};

// ── Main button click ──
const onButtonClick = async () => {
  try {
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'Xiaomi' }],
      optionalServices: ['0000fe95-0000-1000-8000-00805f9b34fb']
    });

    console.log(`✅ Selected: ${device.name} (${device.id})`);

    document.querySelector('.button.start').setAttribute('hidden', '');
    document.querySelector('.form').setAttribute('hidden', '');
    document.querySelector('.loading').removeAttribute('hidden');
    document.querySelector('.loading').textContent = `📡 Listening for ${device.name}... Step on the scale!`;
    document.querySelector('.button.stop').removeAttribute('hidden');

    scan = await navigator.bluetooth.requestLEScan({ acceptAllAdvertisements: true });
    navigator.bluetooth.addEventListener('advertisementreceived', onAdvertisement);

    console.log('✅ Scan started. Bind key loaded. Waiting for encrypted measurement data...');
    console.log(`ℹ️ Bind key: ${BIND_KEY_HEX}`);
    console.log('ℹ️ Close Xiaomi Home app. Step on scale. Wait for measurement to complete.');

  } catch (e) {
    if (e.code === 20 || e.name === 'NotFoundError') return;
    console.error(e);
    alert(`Error: ${e.message}\n\nMake sure chrome://flags/#enable-experimental-web-platform-features is enabled.`);
  }
};

// ── Stop scanning ──
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