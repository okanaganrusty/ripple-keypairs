import * as assert from 'assert'
import * as brorand from 'brorand'
import * as hashjs from 'hash.js'
import * as elliptic from 'elliptic'

import * as addressCodec from './ripple-address-codec'
import {derivePrivateKey, accountPublicFromPublicGenerator} from './secp256k1'
import * as utils from './utils'

const Ed25519 = elliptic.eddsa('ed25519')
const Secp256k1 = elliptic.ec('secp256k1')

const hexToBytes = utils.hexToBytes
const bytesToHex = utils.bytesToHex

function generateSeed(options: {
  entropy?: Uint8Array,
  algorithm?: 'ed25519' | 'secp256k1'
} = {}) {
  assert(!options.entropy || options.entropy.length >= 16, 'entropy too short')
  const entropy = options.entropy ? options.entropy.slice(0, 16) : brorand(16)
  const type = options.algorithm === 'ed25519' ? 'ed25519' : 'secp256k1'
  return addressCodec.encodeSeed(entropy, type)
}

function hash(message) {
  return hashjs.sha512().update(message).digest().slice(0, 32)
}

const secp256k1 = {
  deriveKeypair: function(entropy, options) {
    const prefix = '00'
    const privateKey = prefix + derivePrivateKey(entropy, options)
      .toString(16, 64).toUpperCase()
    const publicKey = bytesToHex(Secp256k1.keyFromPrivate(
      privateKey.slice(2)).getPublic().encodeCompressed())
    return {privateKey, publicKey}
  },
  sign: function(message, privateKey) {
    return bytesToHex(Secp256k1.sign(hash(message),
      hexToBytes(privateKey), {canonical: true}).toDER())
  },
  verify: function(message, signature, publicKey) {
    return Secp256k1.verify(hash(message), signature, hexToBytes(publicKey))
  }
}

const ed25519 = {
  deriveKeypair: function(entropy) {
    const prefix = 'ED'
    const rawPrivateKey = hash(entropy)
    const privateKey = prefix + bytesToHex(rawPrivateKey)
    const publicKey = prefix + bytesToHex(
      Ed25519.keyFromSecret(rawPrivateKey).pubBytes())
    return {privateKey, publicKey}
  },
  sign: function(message, privateKey) {
    // caution: Ed25519.sign interprets all strings as hex, stripping
    // any non-hex characters without warning
    assert(Array.isArray(message), 'message must be array of octets')
    return bytesToHex(Ed25519.sign(
      message, hexToBytes(privateKey).slice(1)).toBytes())
  },
  verify: function(message, signature, publicKey) {
    return Ed25519.verify(message, hexToBytes(signature),
      hexToBytes(publicKey).slice(1))
  }
}

function select(algorithm) {
  const methods = {'ecdsa-secp256k1': secp256k1, ed25519}
  return methods[algorithm]
}

function deriveKeypair(seed, options) {
  const decoded = addressCodec.decodeSeed(seed)
  const algorithm = decoded.type === 'ed25519' ? 'ed25519' : 'ecdsa-secp256k1'
  const method = select(algorithm)
  const keypair = method.deriveKeypair(decoded.bytes, options)
  const messageToVerify = hash('This test message should verify.')
  const signature = method.sign(messageToVerify, keypair.privateKey)
  if (method.verify(messageToVerify, signature, keypair.publicKey) !== true) {
    throw new Error('derived keypair did not generate verifiable signature')
  }
  return keypair
}

function getAlgorithmFromKey(key) {
  const bytes = hexToBytes(key)
  return (bytes.length === 33 && bytes[0] === 0xED) ?
    'ed25519' : 'ecdsa-secp256k1'
}

function sign(messageHex, privateKey) {
  const algorithm = getAlgorithmFromKey(privateKey)
  return select(algorithm).sign(hexToBytes(messageHex), privateKey)
}

function verify(messageHex, signature, publicKey) {
  const algorithm = getAlgorithmFromKey(publicKey)
  return select(algorithm).verify(hexToBytes(messageHex), signature, publicKey)
}

function deriveAddressFromBytes(publicKeyBytes: Buffer) {
  return addressCodec.encodeAccountID(
    utils.computePublicKeyHash(publicKeyBytes))
}

function deriveAddress(publicKey) {
  return deriveAddressFromBytes(hexToBytes(publicKey))
}

function deriveNodeAddress(publicKey) {
  const generatorBytes = addressCodec.decodeNodePublic(publicKey)
  const accountPublicBytes = accountPublicFromPublicGenerator(generatorBytes)
  return deriveAddressFromBytes(accountPublicBytes)
}

const decodeSeed = addressCodec.decodeSeed
const decodeAddress = addressCodec.decodeAccountID

type AddressParts = {
  versionByte: string, // hex
  hash160: string, // 20 bytes = 160 bits, hex
  check: string, // take the versionByte + hash160, perform sha256 twice, and slice the first 4 bytes, hex
  check_valid: boolean,
  version_valid: boolean
}

const baseCodec = require('./ripple-address-codec/base-x')
const createHash = require('create-hash')

// Decode Account ID into its constituent parts
function inspectAddress(address): AddressParts {
  const alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz' // XRP
  const codec = baseCodec(alphabet) // TODO: Cache - do once and reuse result
  const buffer = codec.decode(address) // raw
  if (buffer.length < 5) {
    throw new Error('invalid_input_size: decoded data must have length >= 5')
  }

  const nontaggedAddressDetails = inspectNontaggedAddressBuffer(buffer)
  if (buffer.length === 1 + 20 + 4) {
    return nontaggedAddressDetails
  } else {
    // Tagged Address

    const base32 = baseCodec('ABCDEFGHJKLMNPQRSTUVWXYZ12345679')
    const checksumLength = 3
    const checksum_base32 = address ? address.slice(-checksumLength) : 'TODO: ERROR'

    // Decode last 3 characters
    const checksum = base32.decode(checksum_base32)
    const has_tag = Boolean(checksum & 0x40)
    const crc = checksum ? checksum.slice(-1) : [0]
    const tagLength = 0 // TODO

    return Object.assign({}, nontaggedAddressDetails, {
      address: address ? address.slice(0, -(checksumLength + tagLength)) : 'TODO: ERROR',
      tag: has_tag ? 'TODO' : null,
      checksum_base32,
      checksum: checksum ? checksum.toString('hex') : 'TODO: ERROR',
      crc_valid: true, // TODO
      crc: crc.toString('hex')
    })
  }
}

function inspectNontaggedAddressBuffer(buffer) {
  /**
   * Verify checksum
   */
  const sha256 = function(bytes: Uint8Array) {
    return createHash('sha256').update(Buffer.from(bytes)).digest()
  }
  // Take buffer excluding checksum, sha256 twice, and take first 4 bytes
  const computed = sha256(sha256(buffer.slice(0, -4))).slice(0, 4)
  const check = buffer.slice(-4) // from provided address
  const seqEqual = function(arr1: number[], arr2: number[]) {
    if (arr1.length !== arr2.length) {
      return false
    }

    for (let i = 0; i < arr1.length; i++) {
      if (arr1[i] !== arr2[i]) {
        return false
      }
    }
    return true
  }
  const check_valid = seqEqual(computed, check)
  const withoutSum = buffer.slice(0, -4) // remove checksum (last 4 bytes)

  const payloadLength = 20 // 160 bits, a hash160
  const versionByte = withoutSum.slice(0, 1) // from provided address
  const payload = withoutSum.slice(-payloadLength) // from provided address, hash160

  const version_valid = seqEqual(versionByte, [0]) // ACCOUNT_ID version byte

  return {
    versionByte: versionByte.toString('hex'),
    hash160: payload.toString('hex'),
    check: check.toString('hex'),
    check_valid,
    version_valid
  }
}

module.exports = {
  generateSeed,
  deriveKeypair,
  sign,
  verify,
  deriveAddress,
  deriveNodeAddress,
  decodeSeed,
  decodeAddress,
  inspectAddress
}
