/* eslint-disable radix */
const slipHelper = require('./slip39_helper.js');

const MAX_DEPTH = 2;

//
// Slip39Node
//
class Slip39Node {
  constructor(index = 0, mnemonic = '', children = []) {
    this.mnemonic = mnemonic;
    this.index = index;
    this.children = children;
  }

  get mnemonics() {
    if (this.children.length === 0) {
      return [this.mnemonic];
    }
    const result = this.children.reduce((prev, item) => {
      return prev.concat(item.mnemonics);
    }, []);
    return result;
  }
}

//
// The javascript implementation of the SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes
// see: https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
//
class Slip39 {
  constructor({
    iterationExponent = 0,
    identifier,
    groupCount,
    groupThreshold
  } = {}) {
    this.iterationExponent = iterationExponent;
    this.identifier = identifier;
    this.groupCount = groupCount;
    this.groupThreshold = groupThreshold;
  }

  static fromArray(masterSecret, {
    passphrase = '',
    threshold = 1,
    groups = [
      [1, 1]
    ],
    iterationExponent = 0
  } = {}) {
    if (masterSecret.length * 8 < slipHelper.MIN_ENTROPY_BITS) {
      throw Error(`The length of the master secret (${masterSecret.length} bytes) must be at least ${bitsToBytes(MIN_STRENGTH_BITS)} bytes.`);
    }

    if (masterSecret.length % 2 !== 0) {
      throw Error('The length of the master secret in bytes must be an even number.');
    }

    if (!/^[\x20-\x7E]*$/.test(passphrase)) {
      throw Error('The passphrase must contain only printable ASCII characters (code points 32-126).');
    }

    if (threshold > groups.length) {
      throw Error(`The requested group threshold (${threshold}) must not exceed the number of groups (${groups.length}).`);
    }

    groups.forEach((item) => {
      if (item[0] === 1 && item[1] > 1) {
        throw Error(`Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. ${groups.join()}`);
      }
    });

    const identifier = slipHelper.generateIdentifier();

    const slip = new Slip39({
      iterationExponent: iterationExponent,
      identifier: identifier,
      groupCount: groups.length,
      groupThreshold: threshold
    });

    const ems = slipHelper.crypt(
      masterSecret, passphrase, iterationExponent, slip.identifier);

    const root = slip.buildRecursive(
      new Slip39Node(),
      groups,
      ems,
      threshold
    );

    slip.root = root;
    return slip;
  }

  buildRecursive(current, nodes, secret, threshold, index) {
    // It means it's a leaf.
    if (nodes.length === 0) {
      const mnemonic = slipHelper.encodeMnemonic(this.identifier, this.iterationExponent, index,
        this.groupThreshold, this.groupCount, current.index, threshold, secret);

      current.mnemonic = mnemonic;
      return current;
    }

    const secretShares = slipHelper.splitSecret(threshold, nodes.length, secret);
    let children = [];
    let idx = 0;

    nodes.forEach((item) => {
      // n=threshold
      const n = item[0];
      // m=members
      const m = item[1];

      // Genereate leaf members, means their `m` is `0`
      const members = Array().generate(m, () => [n, 0]);

      const node = new Slip39Node(idx);
      const branch = this.buildRecursive(
        node,
        members,
        secretShares[idx],
        n,
        current.index);

      children = children.concat(branch);
      idx = idx + 1;
    });
    current.children = children;
    return current;
  }

  static recoverSecret(mnemonics, passphrase) {
    return slipHelper.combineMnemonics(mnemonics, passphrase);
  }

  fromPath(path) {
    this.validatePath(path);

    const children = this.parseChildren(path);

    if (typeof children === 'undefined' || children.length === 0) {
      return this.root;
    }

    return children.reduce((prev, childNumber) => {
      let childrenLen = prev.children.length;
      if (childNumber >= childrenLen) {
        throw new Error(`The path index ($childNumber) exceeds the children index (${childrenLen - 1}).`);
      }

      return prev.children[childNumber];
    }, this.root);
  }

  validatePath(path) {
    if (!path.match(/(^r)(\/\d{1,2}){0,2}$/)) {
      throw new Error('Expected valid path e.g. "r/0/0".');
    }

    const depth = path.split('/');
    const pathLength = depth.length - 1;
    if (pathLength > MAX_DEPTH) {
      throw new Error(`Path\'s (${path}) max depth (${MAX_DEPTH}) is exceeded (${pathLength}).`);
    }
  }

  parseChildren(path) {
    const splitted = path.split('/').slice(1);

    const result = splitted.map((pathFragment) => {
      return parseInt(pathFragment);
    });
    return result;
  }
}

exports = module.exports = {
  Slip39,
  Slip39Node
};
