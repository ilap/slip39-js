const assert = require('assert');
const slip39 = require('../src/slip39');

const MS = 'ABCDEFGHIJKLMNOP'.encodeHex();
const PASSPHRASE = 'TREZOR';
const ONE_GROUP = [[5, 7]];

const slip15 = slip39.fromArray(MS, {
  passphrase: PASSPHRASE,
  threshold: 1,
  groups: ONE_GROUP
});

const slip15NoPW = slip39.fromArray(MS, {
  threshold: 1,
  groups: ONE_GROUP
});

//
// Permutations P(n, k) of the grooups
//
function getCombinations(array, k) {
  let result = [];
  let combinations = [];

  function helper(level, start) {
    for (let i = start; i < array.length - k + level + 1; i++) {
      combinations[level] = array[i];

      if (level < k - 1) {
        helper(level + 1, i + 1);
      } else {
        result.push(combinations.slice(0));
      }
    }
  }

  helper(0, 0);
  return result;
}

describe('Basic Tests', () => {
  describe('Test threshold 1 with 5 of 7 shares of a group combinations', () => {
    let mnemonics = slip15.fromPath('r/0').mnemonics;

    let combinations = getCombinations([0, 1, 2, 3, 4, 5, 6], 5);
    combinations.forEach((item) => {
      let description = `Test combination ${item.join(' ')}.`;
      it(description, () => {
        let shares = item.map((idx) => mnemonics[idx]);
        assert(MS.decodeHex() === slip39.recoverSecret(shares, PASSPHRASE)
          .decodeHex());
      });
    });
  });

  describe('Test passhrase', () => {
    let mnemonics = slip15.fromPath('r/0').mnemonics;
    let nopwMnemonics = slip15NoPW.fromPath('r/0').mnemonics;

    it('should return valid mastersecret when user submits valid passphrse', () => {
      assert(MS.decodeHex() === slip39.recoverSecret(mnemonics.slice(0, 5), PASSPHRASE)
        .decodeHex());
    });
    it('should NOT return valid mastersecret when user submits invalid passphrse', () => {
      assert(MS.decodeHex() !== slip39.recoverSecret(mnemonics.slice(0, 5))
        .decodeHex());
    });
    it('should return valid mastersecret when user does not submit passphrse', () => {
      assert(MS.decodeHex() === slip39.recoverSecret(nopwMnemonics.slice(0, 5))
        .decodeHex());
    });
  });

  describe('Test iteration exponent', () => {
    const slip1 = slip39.fromArray(MS, {
      iterationExponent: 1
    });

    const slip2 = slip39.fromArray(MS, {
      iterationExponent: 2
    });

    it('should return valid mastersecret when user apply valid iteration exponent', () => {
      assert(MS.decodeHex() === slip39.recoverSecret(slip1.fromPath('r/0').mnemonics)
        .decodeHex());

      assert(MS.decodeHex() === slip39.recoverSecret(slip2.fromPath('r/0').mnemonics)
        .decodeHex());
    });
    /**
     * assert.throws(() => x.y.z);
     * assert.throws(() => x.y.z, ReferenceError);
     * assert.throws(() => x.y.z, ReferenceError, /is not defined/);
     * assert.throws(() => x.y.z, /is not defined/);
     * assert.doesNotThrow(() => 42);
     * assert.throws(() => x.y.z, Error);
     * assert.throws(() => model.get.z, /Property does not exist in model schema./)
     * Ref: https://stackoverflow.com/questions/21587122/mocha-chai-expect-to-throw-not-catching-thrown-errors
     */
    it('should throw an Error when user submits invalid iteration exponent', () => {
      assert.throws(() => slip39.fromArray(MS, {
        iterationExponent: -1
      }), Error);
      assert.throws(() => slip39.fromArray(MS, {
        iterationExponent: 33
      }), Error);
    });
  });
});

// FIXME: finish it.
describe('Group Shares Tests', () => {
  describe('Test all valid combinations of mnemonics', () => {
    /* const groups = [
      [3, 5],
      [3, 3],
      [2, 5],
      [1, 1]
    ];
    const slip = slip39.fromArray(MS, {
      threshold: 2,
      groups: groups
    });
*/
    it('should return the valid mastersecret when valid mnemonics used for recovery', () => {
      // const root = slip.fromPath('r').mnemonics;
      assert(true);
    });
  });

  describe('Original test vectors Tests', () => {
    let fs = require('fs');
    let path = require('path');
    let filePath = path.join(__dirname, 'vectors.json');

    let content = fs.readFileSync(filePath, 'utf-8');

    const tests = JSON.parse(content);
    tests.forEach((item) => {
      let description = item[0];
      let mnemonics = item[1];
      let masterSecret = Buffer.from(item[2], 'hex');

      it(description, () => {
        if (masterSecret.length !== 0) {
          let ms = slip39.recoverSecret(mnemonics, PASSPHRASE);
          assert(masterSecret.every((v, i) => v === ms[i]));
        } else {
          assert.throws(() => slip39.recoverSecret(mnemonics, PASSPHRASE), Error);
        }
      });
    });
  });

  describe('Invalid Shares', () => {
    const tests = [
      ['Short master secret', 1, [
        [2, 3]
      ], MS.slice(0, 14)],
      ['Odd length master secret', 1, [
        [2, 3]
      ], MS.concat([55])],
      ['Group threshold exceeds number of groups', 3, [
        [3, 5],
        [2, 5]
      ], MS],
      ['Invalid group threshold.', 0, [
        [3, 5],
        [2, 5]
      ], MS],
      ['Member threshold exceeds number of members', 2, [
        [3, 2],
        [2, 5]
      ], MS],
      ['Invalid member threshold', 2, [
        [0, 2],
        [2, 5]
      ], MS],
      ['Group with multiple members and threshold 1', 2, [
        [3, 5],
        [1, 3],
        [2, 5]
      ], MS]
    ];

    tests.forEach((item) => {
      let description = item[0];
      let threshold = item[1];

      let groups = item[2];
      let secret = item[3];

      it(description, () => {
        assert.throws(() =>
          slip39.fromArray(secret, {
            threshold: threshold,
            groups: groups
          }), Error);
      });
    });
  });
});