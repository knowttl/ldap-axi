'use strict';

const { promisify } = require('util');
const { loadBindings } = require('./util');
const { LDAP_AXI_PATCH_LEVEL } = require('./ldap-axi-patch');

const kerberos = loadBindings();
const KerberosClient = kerberos.KerberosClient;

const GSS_C_MUTUAL_FLAG = 2;
const GSS_C_SEQUENCE_FLAG = 8;
const GSS_C_CONF_FLAG = 16;
const GSS_C_INTEG_FLAG = 32;
const GSS_MECH_OID_KRB5 = 9;
const GSS_MECH_OID_SPNEGO = 6;

const promisifiedStep = promisify(KerberosClient.prototype.step);
const promisifiedWrap = promisify(KerberosClient.prototype.wrap);
const promisifiedWrapWithResult = promisify(KerberosClient.prototype.wrapWithResult);
const promisifiedWrapSizeLimit = promisify(KerberosClient.prototype.wrapSizeLimit);
const promisifiedUnwrap = promisify(KerberosClient.prototype.unwrap);
const promisifiedUnwrapWithResult = promisify(KerberosClient.prototype.unwrapWithResult);
const promisifiedInitializeClient = promisify(kerberos.initializeClient);

KerberosClient.prototype.step = async function step(challenge) {
  if (typeof challenge !== 'string') throw new TypeError('parameter `challenge` must be a string.');
  return await promisifiedStep.call(this, challenge);
};

KerberosClient.prototype.wrap = async function wrap(challenge, options = {}) {
  if (typeof challenge !== 'string') throw new TypeError('parameter `challenge` must be a string.');
  return await promisifiedWrap.call(this, challenge, options);
};

KerberosClient.prototype.wrapWithResult = async function wrapWithResult(challenge, options = {}) {
  if (typeof challenge !== 'string') throw new TypeError('parameter `challenge` must be a string.');
  return await promisifiedWrapWithResult.call(this, challenge, options);
};

KerberosClient.prototype.wrapSizeLimit = async function wrapSizeLimit(maxWrappedBytes, options = {}) {
  if (!Number.isSafeInteger(maxWrappedBytes) || maxWrappedBytes <= 0 || maxWrappedBytes > 0xffffffff) {
    throw new RangeError('parameter `maxWrappedBytes` must be a positive 32-bit integer.');
  }
  return await promisifiedWrapSizeLimit.call(this, maxWrappedBytes, options);
};

KerberosClient.prototype.unwrap = async function unwrap(challenge) {
  if (typeof challenge !== 'string') throw new TypeError('parameter `challenge` must be a string.');
  return await promisifiedUnwrap.call(this, challenge);
};

KerberosClient.prototype.unwrapWithResult = async function unwrapWithResult(challenge) {
  if (typeof challenge !== 'string') throw new TypeError('parameter `challenge` must be a string.');
  return await promisifiedUnwrapWithResult.call(this, challenge);
};

async function initializeClient(service, options = {}) {
  if (typeof service !== 'string') throw new TypeError('parameter `service` must be a string.');
  if (options.channelBindingData !== undefined && options.channelBindingData !== null && !(options.channelBindingData instanceof Uint8Array)) {
    throw new TypeError('options.channelBindingData must be binary.');
  }
  if (options.channelBindingData && options.channelBindingData.byteLength > 64 * 1024) {
    throw new RangeError('options.channelBindingData exceeds the 65536-byte limit.');
  }
  const nativeOptions = options.channelBindingData === undefined || options.channelBindingData === null
    ? options
    : { ...options, channelBindingData: Buffer.from(options.channelBindingData) };
  return await promisifiedInitializeClient.call(this, service, nativeOptions);
}

module.exports = {
  initializeClient,
  GSS_C_MUTUAL_FLAG,
  GSS_C_SEQUENCE_FLAG,
  GSS_C_CONF_FLAG,
  GSS_C_INTEG_FLAG,
  GSS_MECH_OID_KRB5,
  GSS_MECH_OID_SPNEGO,
  LDAP_AXI_PATCH_LEVEL,
};
