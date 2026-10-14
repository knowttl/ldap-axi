import assert from "node:assert/strict";
import { Duplex } from "node:stream";
import test from "node:test";
import type { GssapiExchange } from "../../src/directory/gssapi.js";
import { ProtectedSaslDuplex, SaslDataFrameDecoder } from "../../src/directory/protected-stream.js";

class FakeNative extends Duplex {
  readonly writes: Buffer[] = [];

  constructor(backpressure = false) {
    super({ writableHighWaterMark: backpressure ? 1 : 16 * 1024 });
  }

  override _read(): void {}

  override _write(chunk: Uint8Array, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.writes.push(Buffer.from(chunk));
    callback();
  }
}

function exchange(confidential = false, integrity = true): GssapiExchange {
  return {
    initial: async () => Buffer.alloc(0),
    step: async () => ({ token: Buffer.alloc(0), established: true }),
    unwrap: async value => Buffer.from(value),
    unwrapWithResult: async value => ({ token: Buffer.from(value.subarray(1)), confidential, integrity }),
    wrap: async value => Buffer.from(value),
    wrapWithResult: async (value, options) => ({ token: Buffer.concat([Buffer.from([0xa0]), Buffer.from(value)]), confidential: options?.protect === true ? confidential : false, integrity }),
  };
}

function frame(token: Uint8Array): Buffer {
  const output = Buffer.alloc(4 + token.length);
  output.writeUInt32BE(token.length, 0);
  Buffer.from(token).copy(output, 4);
  return output;
}

function write(stream: ProtectedSaslDuplex, value: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => stream.write(value, error => error ? reject(error) : resolve()));
}

function failure(stream: ProtectedSaslDuplex): Promise<Error> {
  return new Promise(resolve => stream.once("error", resolve));
}

test("protected transport custody exposes neither native nor GSS operations", async () => {
  const native = new FakeNative();
  const context = exchange();
  const stream = new ProtectedSaslDuplex(native, context, "integrity", 32, 32, 32, 32);
  stream.on("error", () => undefined);
  const reachable = new Set(Reflect.ownKeys(stream));
  assert.equal(reachable.has("native"), false);
  assert.equal(reachable.has("exchange"), false);
  assert.equal((stream as unknown as Record<string, unknown>).writeNative, undefined);
  assert.equal((stream as unknown as Record<string, unknown>).writeChunk, undefined);
  assert.equal(Object.values(stream).includes(native), false);
  assert.equal(Object.values(stream).includes(context), false);
  stream.destroy();
});

test("protected LDAP writes are bounded, framed, and serialized", async () => {
  const native = new FakeNative(true);
  const stream = new ProtectedSaslDuplex(native, exchange(), "integrity", 3, 32, 32, 32);
  stream.on("error", () => undefined);
  await write(stream, Buffer.from([1, 2, 3, 4, 5, 6, 7]));
  assert.deepEqual(native.writes.map(value => value.readUInt32BE(0)), [4, 4, 2]);
  assert.deepEqual(native.writes.map(value => value.subarray(4)), [Buffer.from([0xa0, 1, 2, 3]), Buffer.from([0xa0, 4, 5, 6]), Buffer.from([0xa0, 7])]);
  stream.destroy();
});

test("protected LDAP reads tolerate fragmented and handoff-buffered frames", async () => {
  const native = new FakeNative();
  const initial = frame(Buffer.from([0xa0, 6, 5, 4]));
  const stream = new ProtectedSaslDuplex(native, exchange(), "integrity", 32, 32, 32, 32, initial);
  stream.on("error", () => undefined);
  const received: Buffer[] = [];
  stream.on("data", value => received.push(Buffer.from(value)));
  const wire = frame(Buffer.from([0xa0, 9, 8, 7]));
  native.push(wire.subarray(0, 2));
  native.push(wire.subarray(2, 5));
  native.push(wire.subarray(5));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(received, [Buffer.from([6, 5, 4]), Buffer.from([9, 8, 7])]);
  stream.destroy();
});

test("orderly native end and close terminate the protected transport once", async () => {
  const native = new FakeNative();
  const stream = new ProtectedSaslDuplex(native, exchange(), "integrity", 32, 32, 32, 32);
  let ends = 0;
  let closes = 0;
  let errors = 0;
  stream.on("end", () => { ends += 1; });
  stream.on("close", () => { closes += 1; });
  stream.on("error", () => { errors += 1; });
  stream.resume();
  const closed = new Promise<void>(resolve => stream.once("close", resolve));
  native.emit("end");
  native.emit("close");
  await closed;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(stream.destroyed, true);
  assert.equal(ends, 1);
  assert.equal(closes, 1);
  assert.equal(errors, 0);
});

test("protected LDAP pauses native input while unwrap is pending", async () => {
  const native = new FakeNative();
  let releaseFirst: (() => void) | undefined;
  const firstPending = new Promise<void>(resolve => { releaseFirst = resolve; });
  let unwraps = 0;
  let secondStarted: (() => void) | undefined;
  const secondStartedPromise = new Promise<void>(resolve => { secondStarted = resolve; });
  const slowExchange: GssapiExchange = {
    ...exchange(),
    unwrapWithResult: async value => {
      unwraps += 1;
      if (unwraps === 1) await firstPending;
      else secondStarted?.();
      return { token: Buffer.from(value.subarray(1)), confidential: false, integrity: true };
    },
  };
  const stream = new ProtectedSaslDuplex(native, slowExchange, "integrity", 32, 32, 32, 32);
  stream.on("error", () => undefined);
  stream.resume();
  native.push(frame(Buffer.from([0xa0, 1])));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(unwraps, 1);
  assert.equal(native.isPaused(), true);

  native.push(frame(Buffer.from([0xa0, 2])));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(unwraps, 1);
  releaseFirst?.();
  await secondStartedPromise;
  assert.equal(unwraps, 2);
  stream.destroy();
});

test("protected LDAP rejects oversized, truncated, and unproven frames", async () => {
  const decoder = new SaslDataFrameDecoder(3);
  assert.throws(() => decoder.push(frame(Buffer.alloc(4))), /failed/);
  const truncated = new SaslDataFrameDecoder(3);
  truncated.push(Buffer.from([0, 0, 0]));
  assert.throws(() => truncated.finish(), /failed/);

  const native = new FakeNative();
  const stream = new ProtectedSaslDuplex(native, exchange(false, false), "integrity", 32, 32, 32, 32);
  stream.on("error", () => undefined);
  await assert.rejects(write(stream, Buffer.from([1])), /failed/);
  stream.destroy();

  const confidentiality = new FakeNative();
  const confidentialStream = new ProtectedSaslDuplex(confidentiality, exchange(false, true), "confidentiality", 32, 32, 32, 32);
  confidentialStream.on("error", () => undefined);
  await assert.rejects(write(confidentialStream, Buffer.from([1])), /failed/);
  confidentialStream.destroy();
});

test("rejected inbound frames release no unwrapped bytes", async () => {
  const cases: ReadonlyArray<{ token: Buffer; context: GssapiExchange; maxWrappedBytes: number; end?: boolean }> = [
    { token: Buffer.alloc(4), context: exchange(), maxWrappedBytes: 3 },
    { token: Buffer.from([0xa0, 1]), context: exchange(false, false), maxWrappedBytes: 32 },
    { token: Buffer.from([0xa0, ...Buffer.alloc(33)]), context: exchange(), maxWrappedBytes: 64 },
    { token: Buffer.from([0, 0, 0]), context: exchange(), maxWrappedBytes: 32, end: true },
  ];
  for (const item of cases) {
    const native = new FakeNative();
    const stream = new ProtectedSaslDuplex(native, item.context, "integrity", 32, 64, 32, item.maxWrappedBytes);
    const received: Buffer[] = [];
    stream.on("data", value => received.push(Buffer.from(value)));
    const failed = failure(stream);
    native.push(item.end ? item.token : frame(item.token));
    if (item.end) native.push(null);
    assert.match((await failed).message, /failed/);
    assert.deepEqual(received, []);
    assert.equal(native.destroyed, true);
  }
});
