const assert = require('assert');
const slip39 = require('../src/slip39');

const MS = 'ABCDEFGHIJKLMNOP'.encodeHex();
const PASSPHRASE = 'TREZOR';
const ONE_GROUP = [
  [5, 7]
];

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
// Shuffle
//
function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

//
// Combination C(n, k) of the grooups
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
      shuffle(item);
      let description = `Test shuffled combination ${item.join(' ')}.`;
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
describe('Group Sharing Tests', () => {
  describe('Test all valid combinations of mnemonics', () => {
    const groups = [
      [3, 5],
      [3, 3],
      [2, 5],
      [1, 1]
    ];
    const slip = slip39.fromArray(MS, {
      threshold: 2,
      groups: groups
    });

    const group2Mnemonics = slip.fromPath('r/2').mnemonics;
    const group3Mnemonic = slip.fromPath('r/3').mnemonics[0];

    it('Should return the valid master secret when it tested with minimal sets of mnemonics.', () => {
      const mnemonics = group2Mnemonics.filter((_, index) => {
        return index === 0 || index === 2;
      }).concat(group3Mnemonic);

      assert(MS.decodeHex() === slip39.recoverSecret(mnemonics).decodeHex());
    });
    it('TODO: Should NOT return the valid master secret when one complete group and one incomplete group out of two groups required', () => {
      assert(true);
    });
    it('TODO: Should return the valid master secret when one group of two required but only one applied.', () => {
      assert(true);
    });
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

describe('Mnemonic Validation', () => {
  describe('Valid Mnemonics', () => {
    let mnemonics = slip15.fromPath('r/0').mnemonics;

    mnemonics.forEach((mnemonic, index) => {
      it (`Mnemonic at index ${index} should be valid`, () => {
        const isValid = slip39.validateMnemonic(mnemonic);

        assert(isValid);
      });
    });
  });

  const vectors = [
    [
      "2. Mnemonic with invalid checksum (128 bits)",
      [
        "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
      ]
    ],
    [
      "21. Mnemonic with invalid checksum (256 bits)",
      [
        "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
      ]
    ],
    [
      "3. Mnemonic with invalid padding (128 bits)",
      [
        "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
      ]
    ],
    [
      "22. Mnemonic with invalid padding (256 bits)",
      [
        "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister"
      ]
    ],
    [
      "10. Mnemonics with greater group threshold than group counts (128 bits)",
      [
        "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
        "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
        "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce"
      ]
    ],
    [
      "29. Mnemonics with greater group threshold than group counts (256 bits)",
      [
        "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
        "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
        "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful"
      ]
    ],
    [
      "39. Mnemonic with insufficient length",
      [
        "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
      ]
    ],
    [
      "40. Mnemonic with invalid master secret length",
      [
        "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter"
      ]
    ]
  ];

  vectors.forEach((item) => {
    const description = item[0];
    const mnemonics = item[1];

    describe(description, () => {
      mnemonics.forEach((mnemonic, index) => {
        it (`Mnemonic at index ${index} should be invalid`, () => {
          const isValid = slip39.validateMnemonic(mnemonic);

          assert(isValid === false);
        });
      });
    });
  });
});

// See https://github.com/satoshilabs/slips/blob/master/slip-0039.md#notation
// particularly the table rows:
// "total number of groups, a positive integer, 1 ≤ G ≤ 16"
// "group threshold, a positive integer, 1 ≤ GT ≤ G"
// This test also fails for 15-of-16, 15-of-15, but passes for all other combos
describe('Maximum number of shares ie 16-of-16', () => {
  // generate the shares
  let masterSecretHex = "d2b5e45b2934281a118ece2ae498514d";
  let masterSecretBuff = Buffer.from(masterSecretHex, 'hex');
  let masterSecret = [];
  for (i = 0; i<masterSecretBuff.length; i++) {
      masterSecret.push(masterSecretBuff[i]);
  }
  let passphrase = "TREZOR";
  let totalGroups = 16;
  let threshold = 16;
  let groups = [];
  for (i = 0; i < totalGroups; i++) {
      groups.push([1,1]);
  }
  const slip = slip39.fromArray(masterSecret, {
    passphrase: passphrase,
    threshold: threshold,
    groups: groups,
  });
  // extract the required number of mnemonics for recovery
  let mnemonics = [];
  for (i = 0; i < threshold; i++) {
    let mnemonic = slip.fromPath('r/' + i).mnemonics[0];
    console.log(mnemonic);
    mnemonics.push(mnemonic);
  }
  // check the mnemonics recover to the original master secret
  it("Recovers master secret when there are 16-of-16 shares", () => {
    let ms = slip39.recoverSecret(mnemonics, passphrase);
    assert(masterSecret.every((v, i) => v === ms[i]));
  });
});
