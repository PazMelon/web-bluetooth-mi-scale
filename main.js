import Metrics from './metrics'

let scan = null;
const BIND_KEY_HEX = 'fe124135b623f23c202f4dae69d41836';
const BIND_KEY = hexToBytes(BIND_KEY_HEX);
const DEVICE_MAC = new Uint8Array([0x99, 0xA9, 0x17, 0x1C, 0xFA, 0x34]);

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

const parseS400Value = (value) => {
  const rawWeight = value & 0x7FF;          
  const rawHR = (value >> 11) & 0x7F;       
  const rawImpedance = value >> 18;          

  return {
    weight: rawWeight !== 0 ? rawWeight / 10 : 0,
    heartRate: (rawHR > 0 && rawHR < 127) ? rawHR + 50 : 0,
    impedance: rawImpedance !== 0 ? rawImpedance / 10 : 0,
  };
};

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
  if (hasMac) { mac = new Uint8Array(dataView.buffer, dataView.byteOffset + offset, 6); offset += 6; }
  if (hasCapability) offset += 1;

  return { frameControl, productId, frameCounter, version, isEncrypted, hasMac, hasCapability, hasObject, mac, offset };
};

async function decryptMiBeaconV4V5(fullData, headerOffset) {
  if (fullData.length < headerOffset + 7) return null;
  const nonce = new Uint8Array(12);
  nonce.set(DEVICE_MAC, 0);                                          
  nonce.set(fullData.slice(2, 5), 6);                                
  nonce.set(fullData.slice(fullData.length - 7, fullData.length - 4), 9); 

  const encryptedPayload = fullData.slice(headerOffset, fullData.length - 7);
  const key = await crypto.subtle.importKey('raw', BIND_KEY, { name: 'AES-CTR' }, false, ['encrypt']);

  const counterBlock = new Uint8Array(16);
  counterBlock[0] = 2; 
  counterBlock.set(nonce, 1); 
  counterBlock[15] = 1; 

  const decrypted = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter: counterBlock, length: 24 }, 
    key, encryptedPayload
  );
  return new Uint8Array(decrypted);
}

function parseDecryptedObject(data) {
  if (data.length < 7) return null;
  const objectId = data[0] | (data[1] << 8);
  const dataLen = data[2];
  const piid = data[3]; 

  let packedValue = 0;
  for (let i = 0; i < 4 && (4 + i) < data.length; i++) {
    packedValue |= data[4 + i] << (i * 8);
  }
  packedValue = packedValue >>> 0;
  return { objectId, dataLen, piid, packedValue };
}

// ============== STATE MACHINE & KIOSK LOGIC ==============

let currentStudent = null;
let currentInputId = 'C';
const API_BASE = 'http://localhost:3000/api';

const VIEWS = {
  ADMIN: 'view-admin',
  INPUT: 'view-input',
  MEASURE: 'view-measure',
  SUCCESS: 'view-success'
};

function switchView(viewId) {
  Object.values(VIEWS).forEach(v => {
    document.getElementById(v).classList.remove('active');
  });
  document.getElementById(viewId).classList.add('active');
}

// -- Numpad Logic --
document.querySelectorAll('.num-key[data-val]').forEach(btn => {
  btn.addEventListener('click', () => {
    if (currentInputId.length < 15) {
      currentInputId += btn.getAttribute('data-val');
      updateIdDisplay();
    }
  });
});

document.getElementById('btn-del').addEventListener('click', () => {
    if (currentInputId.length > 1) {
        currentInputId = currentInputId.slice(0, -1);
        updateIdDisplay();
    }
});

function updateIdDisplay() {
  document.getElementById('id-display').innerText = currentInputId;
  document.getElementById('input-error').innerText = '';
}

// -- Submit Student ID --
document.getElementById('btn-enter').addEventListener('click', async () => {
  if (!currentInputId) return;
  
  const errorEl = document.getElementById('input-error');
  errorEl.innerText = 'Validating...';

  try {
      const res = await fetch(`${API_BASE}/student/${currentInputId}`);
      const data = await res.json();
      
      if (data.success) {
          currentStudent = data.student;
          startMeasurementProcess();
      } else {
          errorEl.innerText = data.message || 'Student ID not found';
          currentInputId = 'C';
          updateIdDisplay();
      }
  } catch(e) {
      console.error(e);
      errorEl.innerText = 'Server connection error';
  }
});

// -- Measurement Logic --

let isMeasuring = false;
let weightHistory = []; // To check stabilization
let stabilizedWeight = 0;
let finalHeartRate = 0;
let hrTimeoutId = null; 

function startMeasurementProcess() {
  const nameDisplay = `${currentStudent.first_name || ''} ${currentStudent.last_name || ''}`.trim() || 'Unknown Student';
  document.getElementById('measuring-name').innerText = nameDisplay;
  
  document.querySelector('.loader-ring').style.display = 'block';
  document.querySelector('#view-measure h2').innerText = 'Ready to Take Measurement';
  document.querySelector('#view-measure p').innerText = 'Waiting for scale...';
  
  document.getElementById('live-values').style.display = 'none';
  document.getElementById('live-weight').innerText = '--';
  document.getElementById('live-hr').innerHTML = '-- <small style="font-size:14px">bpm</small>';

  isMeasuring = true;
  weightHistory = [];
  stabilizedWeight = 0;
  finalHeartRate = 0;
  switchView(VIEWS.MEASURE);
}

document.getElementById('btn-cancel').addEventListener('click', () => {
  resetKiosk();
});

function resetKiosk() {
  isMeasuring = false;
  currentStudent = null;
  currentInputId = 'C';
  updateIdDisplay();
  clearTimeout(hrTimeoutId);
  switchView(VIEWS.INPUT);
}

const onAdvertisement = async (event) => {
  if (!isMeasuring) return; // Only process when we are actively measuring a student
  
  if (event.serviceData && event.serviceData.size > 0) {
    event.serviceData.forEach(async (dataView, uuid) => {
      const uuidStr = typeof uuid === 'string' ? uuid : uuid.toString();
      if (uuidStr.includes('fe95')) {
        const beacon = parseMiBeacon(dataView);
        if (!beacon) return;
        
        let parsedData = null;

        if (beacon.isEncrypted && beacon.hasObject) {
          const fullData = new Uint8Array(dataView.buffer, dataView.byteOffset, dataView.byteLength);
          try {
            const decrypted = await decryptMiBeaconV4V5(fullData, beacon.offset);
            if (decrypted) {
              const obj = parseDecryptedObject(decrypted);
              if (obj && obj.packedValue > 0) {
                parsedData = parseS400Value(obj.packedValue);
              }
            }
          } catch (e) {
             console.warn('Decryption fail', e);
          }
        } else if (!beacon.isEncrypted && beacon.hasObject) {
            const eventData = new Uint8Array(dataView.buffer, dataView.byteOffset + beacon.offset, dataView.byteLength - beacon.offset);
            const obj = parseDecryptedObject(eventData);
            if (obj && obj.eventValue > 1) {
              parsedData = parseS400Value(obj.eventValue);
            }
        }
        
        if (parsedData && parsedData.weight > 0) {
            processMeasurement(parsedData.weight, parsedData.heartRate);
        }

      }
    });
  }
};

function processMeasurement(weight, hr) {
    if (!isMeasuring) return;

    // Show live UI
    document.querySelector('.loader-ring').style.display = 'none';
    document.querySelector('#view-measure h2').innerText = 'Measuring...';
    document.querySelector('#view-measure p').innerText = 'Please stand still.';
    document.getElementById('live-values').style.display = 'flex';
    document.getElementById('live-weight').innerText = weight.toFixed(2);
    if (hr > 0) {
        document.getElementById('live-hr').innerHTML = `${hr} <small style="font-size:14px">bpm</small>`;
    }
    
    // If we receive a heart rate > 0, the scale has definitely finished taking ALL measurements (including impedance/HR)
    if (hr > 0) {
        stabilizedWeight = weight;
        finalHeartRate = hr;
        finalizeMeasurement();
        return;
    }

    // Check for weight stabilization (4 identical weights in a row)
    if (stabilizedWeight === 0) {
        weightHistory.push(weight);
        if (weightHistory.length > 4) weightHistory.shift();

        if (weightHistory.length === 4 && weightHistory.every(w => w === weight)) {
             stabilizedWeight = weight;
             document.querySelector('#view-measure p').innerText = 'Weight captured...';
             
             // Since HR usually comes at the same time or immediately after, 
             // we only wait 3.5 seconds. If the HR calculation failed on the 
             // scale, it just broadcasts the weight forever, so we must timeout.
             hrTimeoutId = setTimeout(() => {
                 if (isMeasuring && finalHeartRate === 0) {
                     finalizeMeasurement();
                 }
             }, 3500);
        }
    } 
}

async function finalizeMeasurement() {
    isMeasuring = false;
    clearTimeout(hrTimeoutId);

    // Go to success screen immediately
    document.getElementById('final-weight').innerText = `${stabilizedWeight.toFixed(2)} kg`;
    document.getElementById('final-hr').innerText = finalHeartRate > 0 ? `${finalHeartRate} bpm` : 'N/A';
    switchView(VIEWS.SUCCESS);

    try {
        await fetch(`${API_BASE}/vitals`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: currentStudent.profile_id,
                weight_kg: stabilizedWeight,
                heart_rate: finalHeartRate > 0 ? finalHeartRate : null
            })
        });
    } catch (e) {
        console.error('Failed to save to database', e);
    }

    // Reset after 5 seconds
    setTimeout(() => {
        resetKiosk();
    }, 5000);
}


// -- BT Init Logic --
document.getElementById('btn-connect').addEventListener('click', async () => {
  try {
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'Xiaomi' }],
      optionalServices: ['0000fe95-0000-1000-8000-00805f9b34fb']
    });

    scan = await navigator.bluetooth.requestLEScan({ acceptAllAdvertisements: true });
    navigator.bluetooth.addEventListener('advertisementreceived', onAdvertisement);

    const statusEl = document.getElementById('ble-status');
    statusEl.innerText = '🟢 Connected to ' + device.name;
    statusEl.classList.add('connected');
    
    // Automatically switch to Input view after 1.5 seconds
    setTimeout(() => {
        switchView(VIEWS.INPUT);
    }, 1500);

  } catch (e) {
      alert(`Error starting Bluetooth: ${e.message}`);
  }
});