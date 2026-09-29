import assert from 'node:assert/strict';
import test from 'node:test';
import {perform, selectQASimulator} from './simulator_biometrics.mjs';

const udid = '1D3A51F4-34CC-41F9-9AE7-BEF5687EF6C3';
const device = {udid, name: 'Layergram Keyboard Validation', state: 3};
const options = {udid, consent: 'YES'};

test('only exact booted disposable QA simulator is selected', () => {
  assert.equal(selectQASimulator([device], udid, 'YES'), device);
  for (const rows of [[], [device, device], [{...device, state: 1}], [{...device, name: 'Personal iPhone'}]]) {
    assert.throws(() => selectQASimulator(rows, udid, 'YES'));
  }
  assert.throws(() => selectQASimulator([device], udid, 'NO'));
  assert.throws(() => selectQASimulator([device], '00008120-000244E00E6BC01E', 'YES'));
});

function mock(enrolled = true) {
  return {
    calls: [],
    getDevices: async () => [device],
    isBiometricEnrolled: async () => enrolled,
    enrollBiometric: async function(id, enabled) { this.calls.push(['enroll', id, enabled]); enrolled = enabled; },
    sendBiometricMatch: async function(...args) { this.calls.push(['match', ...args]); },
  };
}

test('unknown command and missing consent cause no injection', async () => {
  const sim = mock();
  await assert.rejects(perform(sim, {...options, action: 'unlockPhone'}));
  await assert.rejects(perform(sim, {...options, consent: 'NO', action: 'enrolled'}));
  assert.deepEqual(sim.calls, []);
});

test('status is read only and enrollment is read back', async () => {
  const sim = mock(false);
  assert.equal(await perform(sim, {...options, action: 'status'}), false);
  assert.deepEqual(sim.calls, []);
  assert.equal(await perform(sim, {...options, action: 'enrolled'}), true);
  assert.equal(await perform(sim, {...options, action: 'unenrolled'}), false);
  assert.deepEqual(sim.calls, [['enroll', udid, true], ['enroll', udid, false]]);
});

test('sensor events use Face ID and exact target without enrolling silently', async () => {
  const sim = mock();
  await perform(sim, {...options, action: 'match'});
  await perform(sim, {...options, action: 'nonmatch'});
  assert.deepEqual(sim.calls, [['match', udid, true, 'faceId'], ['match', udid, false, 'faceId']]);
  const empty = mock(false);
  await assert.rejects(perform(empty, {...options, action: 'match'}));
  assert.deepEqual(empty.calls, []);
});

test('incorrect enrollment read-back is a failure', async () => {
  const sim = mock(false);
  sim.enrollBiometric = async () => {};
  await assert.rejects(perform(sim, {...options, action: 'enrolled'}));
});
