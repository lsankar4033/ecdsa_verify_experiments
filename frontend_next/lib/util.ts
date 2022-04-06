const snarkjs = require("snarkjs");
const pkg = require("@noble/secp256k1");
const { Point, sign } = pkg;

// bigendian
function bigint_to_Uint8Array(x: bigint) {
  var ret = new Uint8Array(32);
  for (var idx = 31; idx >= 0; idx--) {
    ret[idx] = Number(x % 256n);
    x = x / 256n;
  }
  return ret;
}

// bigendian
function Uint8Array_to_bigint(x: Uint8Array) {
  var ret = 0n;
  for (var idx = 0; idx < x.length; idx++) {
    ret = ret * 256n;
    ret = ret + BigInt(x[idx]);
  }
  return ret;
}

function bigint_to_array(n: number, k: number, x: bigint) {
  let mod = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret = [];
  var x_temp = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

// example sig taken from https://github.com/0xPARC/circom-ecdsa/blob/master/test/ecdsa.test.ts#L130
const priv =
  88549154299169935420064281163296845505587953610183896504176354567359434168161n;
const pubkey = Point.fromPrivateKey(priv);
const msghashBigint = 1234n;
export const prepareInput = async function () {
  const msghash = bigint_to_Uint8Array(msghashBigint);
  const pubX = pubkey.x;
  const pubY = pubkey.y;

  const sig = await sign(msghash, bigint_to_Uint8Array(priv), {
    canonical: true,
    der: false,
  });
  const r = sig.slice(0, 32);
  const r_bigint = Uint8Array_to_bigint(r);
  const s = sig.slice(32, 64);
  const s_bigint = Uint8Array_to_bigint(s);
  const r_array = bigint_to_array(64, 4, r_bigint);
  const s_array = bigint_to_array(64, 4, s_bigint);
  const msghash_array = bigint_to_array(64, 4, msghashBigint);
  const pub0_array = bigint_to_array(64, 4, pubX);
  const pub1_array = bigint_to_array(64, 4, pubY);

  return {
    r: r_array,
    s: s_array,
    msghash: msghash_array,
    pubkey: [pub0_array, pub1_array],
  };
};

export const calculateProof = async function (input: any) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    "./ECDSAVerifyNoPubkeyCheck_64-4_prod.wasm",
    "./ECDSAVerifyNoPubkeyCheck_64-4_prod.0.zkey"
  );

  return {
    proof,
    publicSignals,
  };
};

export const verifyProof = async function (proof, publicSignals) {
  const vkey = await snarkjs.zKey.exportVerificationKey(
    "./ECDSAVerifyNoPubkeyCheck_64-4_prod.0.zkey"
  );

  const res = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  return res;
};
