// Simulator-only sensor injection through Appium CoreSimulator controls.
// Never changes enrollment or authentication on a physical device.
import {pathToFileURL} from 'node:url';

const actions = new Set(['status', 'enrolled', 'unenrolled', 'match', 'nonmatch']);

export function selectQASimulator(devices, udid, consent) {
  if (consent !== 'YES') throw new Error('Explicit disposable simulator consent required');
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(udid ?? '')) {
    throw new Error('An exact simulator UUID is required; physical identifiers are refused');
  }
  const matches = devices.filter(device => device.udid === udid);
  if (matches.length !== 1 || !matches[0].name.startsWith('Layergram ') || matches[0].state !== 3) {
    throw new Error('Select exactly one booted Layergram QA simulator');
  }
  return matches[0];
}

export async function perform(sim, {udid, consent, action}) {
  if (!actions.has(action)) throw new Error('Unknown simulator biometric action');
  selectQASimulator(await sim.getDevices(), udid, consent);
  if (action === 'enrolled' || action === 'unenrolled') {
    const expected = action === 'enrolled';
    await sim.enrollBiometric(udid, expected);
    if (await sim.isBiometricEnrolled(udid) !== expected) throw new Error('Enrollment read-back failed');
  } else if (action === 'match' || action === 'nonmatch') {
    if (!await sim.isBiometricEnrolled(udid)) throw new Error('Simulator biometric sensor is not enrolled');
    await sim.sendBiometricMatch(udid, action === 'match', 'faceId');
  }
  return await sim.isBiometricEnrolled(udid);
}

async function main() {
  const [action, udid] = process.argv.slice(2);
  const consent = process.env.LAYERGRAM_KEYBOARD_DISPOSABLE_SIMULATOR;
  // Reject physical IDs and missing consent before loading the native library.
  selectQASimulator([{udid, name: 'Layergram preflight', state: 3}], udid, consent);
  if (!actions.has(action)) throw new Error('Use status|enrolled|unenrolled|match|nonmatch and exact simulator UUID');
  const modulePath = process.env.LAYERGRAM_QA_CORESIM_MODULE;
  if (!modulePath?.startsWith('/')) throw new Error('Select the installed @appium/coresim module with an absolute path');
  const {NativeSimctl} = await import(pathToFileURL(modulePath).href);
  const enrolled = await perform(new NativeSimctl(), {udid, consent, action});
  console.log(`QA_SIM_BIOMETRIC=${action};enrolled=${enrolled};simulationOnly`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 2; });
}
