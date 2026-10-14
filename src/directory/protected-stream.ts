import { Duplex } from "node:stream";
import type { GssapiExchange, GssapiUnwrapResult, GssapiWrapResult } from "./gssapi.js";
import { SASL_MAX_LDAP_MESSAGE_BYTES, SASL_MAX_WRAPPED_BYTES } from "./sasl.js";

const SASL_FRAME_HEADER_BYTES = 4;
const MAX_FRAMES_PER_CHUNK = 256;
const PROTECTED_TRANSPORT_ERROR = "GSSAPI protected LDAP transport failed";

type NativeStream = Duplex & {
  pause: () => NativeStream;
  resume: () => NativeStream;
};

function transportError(): Error {
  return new Error(PROTECTED_TRANSPORT_ERROR);
}

function validResult(result: GssapiWrapResult | GssapiUnwrapResult): result is GssapiWrapResult | GssapiUnwrapResult {
  return Boolean(result) && result.token instanceof Uint8Array && typeof result.confidential === "boolean" && typeof result.integrity === "boolean";
}

/** Decodes RFC 4422's four-octet network-order protected-data framing without buffering unbounded input. */
export class SaslDataFrameDecoder {
  private header = Buffer.alloc(0);
  private frame: Buffer | undefined;
  private offset = 0;
  private frames = 0;

  constructor(private readonly maxFrameBytes = SASL_MAX_WRAPPED_BYTES) {
    if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes <= 0 || maxFrameBytes > 0xffffffff) throw new RangeError("SASL frame limit is invalid");
  }

  get pending(): boolean {
    return this.header.length !== 0 || this.frame !== undefined;
  }

  push(chunk: Uint8Array): readonly Buffer[] {
    if (!(chunk instanceof Uint8Array)) throw transportError();
    const frames: Buffer[] = [];
    let offset = 0;
    while (offset < chunk.length) {
      if (!this.frame) {
        const needed = SASL_FRAME_HEADER_BYTES - this.header.length;
        const count = Math.min(needed, chunk.length - offset);
        this.header = Buffer.concat([this.header, Buffer.from(chunk.subarray(offset, offset + count))]);
        offset += count;
        if (this.header.length < SASL_FRAME_HEADER_BYTES) continue;
        const length = this.header.readUInt32BE(0);
        this.header = Buffer.alloc(0);
        if (length > this.maxFrameBytes) throw transportError();
        this.frame = Buffer.alloc(length);
        this.offset = 0;
        if (length === 0) {
          frames.push(this.frame);
          this.frame = undefined;
          this.frames += 1;
          if (this.frames > MAX_FRAMES_PER_CHUNK) throw transportError();
        }
      }
      if (this.frame) {
        const count = Math.min(this.frame.length - this.offset, chunk.length - offset);
        chunk.subarray(offset, offset + count).forEach((value, index) => { this.frame![this.offset + index] = value; });
        this.offset += count;
        offset += count;
        if (this.offset === this.frame.length) {
          frames.push(this.frame);
          this.frame = undefined;
          this.offset = 0;
          this.frames += 1;
          if (this.frames > MAX_FRAMES_PER_CHUNK) throw transportError();
        }
      }
    }
    this.frames = 0;
    return frames;
  }

  finish(): void {
    if (this.pending) throw transportError();
  }
}

/**
 * A sealed Duplex boundary installed only after SASL negotiation succeeds.
 * It exposes no native socket or GSS primitive; all protocol bytes cross the boundary as protected frames.
 */
export class ProtectedSaslDuplex extends Duplex {
  readonly #decoder: SaslDataFrameDecoder;
  readonly #native: NativeStream;
  readonly #exchange: GssapiExchange;
  readonly #protection: "integrity" | "confidentiality";
  readonly #maxPlaintextBytes: number;
  readonly #maxWrappedBytes: number;
  readonly #maxInboundPlaintextBytes: number;
  #inboundWork = Promise.resolve();
  #writeWork = Promise.resolve();
  #contextWork = Promise.resolve();
  #readWaiter: (() => void) | undefined;
  #pausedForBackpressure = false;
  #terminated = false;
  #sawEnd = false;

  constructor(
    native: NativeStream,
    exchange: GssapiExchange,
    protection: "integrity" | "confidentiality",
    maxPlaintextBytes: number,
    maxWrappedBytes: number,
    maxInboundPlaintextBytes: number,
    maxInboundWrappedBytes: number,
    initialData: Uint8Array = Buffer.alloc(0),
  ) {
    super();
    if ([maxPlaintextBytes, maxWrappedBytes, maxInboundPlaintextBytes, maxInboundWrappedBytes].some(value => !Number.isSafeInteger(value) || value <= 0)) throw transportError();
    this.#native = native;
    this.#exchange = exchange;
    this.#protection = protection;
    this.#maxPlaintextBytes = maxPlaintextBytes;
    this.#maxWrappedBytes = maxWrappedBytes;
    this.#maxInboundPlaintextBytes = maxInboundPlaintextBytes;
    this.#decoder = new SaslDataFrameDecoder(maxInboundWrappedBytes);
    native.pause();
    native.on("data", data => this.#enqueueInbound(data));
    native.once("end", () => {
      this.#sawEnd = true;
      this.#inboundWork.then(() => {
        if (this.#terminated) return;
        try {
          this.#decoder.finish();
          this.push(null);
        } catch {
          this.#fail();
        }
      }).catch(() => { this.#fail(); });
    });
    native.once("error", () => this.#fail());
    native.once("close", () => {
      if (!this.#sawEnd) { this.#fail(); return; }
      this.#inboundWork.then(() => {
        setImmediate(() => { if (!this.#terminated) this.destroy(); });
      }).catch(() => { this.#fail(); });
    });
    if (initialData.length) this.#enqueueInbound(initialData);
    else native.resume();
  }

  override _read(): void {
    if (this.#pausedForBackpressure) {
      this.#pausedForBackpressure = false;
      const waiter = this.#readWaiter;
      this.#readWaiter = undefined;
      waiter?.();
    }
  }

  override _write(chunk: Uint8Array, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    const work = this.#writeWork.then(() => this.#writePlaintext(chunk));
    this.#writeWork = work.then(() => undefined, () => undefined);
    work.then(() => callback(), () => callback(transportError()));
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.#terminated) { callback(); return; }
    this.#native.end(() => callback());
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    if (!this.#terminated) {
      this.#terminated = true;
      this.#native.destroy();
    }
    callback(error ? transportError() : undefined);
  }

  #fail(): void {
    if (this.#terminated) return;
    this.#terminated = true;
    this.#native.destroy();
    this.destroy(transportError());
  }

  async #withContext<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#contextWork.then(operation);
    this.#contextWork = result.then(() => undefined, () => undefined);
    return result;
  }

  async #writePlaintext(chunk: Uint8Array): Promise<void> {
    if (!(chunk instanceof Uint8Array) || chunk.length > SASL_MAX_LDAP_MESSAGE_BYTES * 16) throw transportError();
    if (chunk.length === 0) {
      await this.#writeChunk(Buffer.alloc(0));
      return;
    }
    for (let offset = 0; offset < chunk.length; offset += this.#maxPlaintextBytes) {
      await this.#writeChunk(Buffer.from(chunk.subarray(offset, Math.min(offset + this.#maxPlaintextBytes, chunk.length))));
    }
  }

  async #writeChunk(plaintext: Buffer): Promise<void> {
    if (!this.#exchange.wrapWithResult) throw transportError();
    const result = await this.#withContext(() => this.#exchange.wrapWithResult!(plaintext, { protect: this.#protection === "confidentiality" }));
    if (!validResult(result) || result.integrity !== true || this.#protection === "confidentiality" && result.confidential !== true) throw transportError();
    if (result.token.length > this.#maxWrappedBytes) throw transportError();
    const frame = Buffer.alloc(SASL_FRAME_HEADER_BYTES + result.token.length);
    frame.writeUInt32BE(result.token.length, 0);
    Buffer.from(result.token).copy(frame, SASL_FRAME_HEADER_BYTES);
    await this.#writeNative(frame);
  }

  async #writeNative(frame: Buffer): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      let callbackDone = false;
      let drainDone = true;
      let settled = false;
      const finish = (error?: Error | null): void => {
        if (settled) return;
        if (error) { settled = true; reject(transportError()); return; }
        if (callbackDone && drainDone) { settled = true; resolve(); }
      };
      const onDrain = (): void => { drainDone = true; finish(); };
      try {
        const accepted = this.#native.write(frame, error => {
          callbackDone = true;
          finish(error);
        });
        if (!accepted) {
          drainDone = false;
          this.#native.once("drain", onDrain);
        }
      } catch {
        finish(transportError());
      }
    });
  }

  #enqueueInbound(data: Uint8Array): void {
    this.#native.pause();
    this.#inboundWork = this.#inboundWork.then(async () => {
      await this.#receive(data);
      if (!this.#terminated && !this.#pausedForBackpressure) this.#native.resume();
    }).catch(() => { this.#fail(); });
  }

  async #receive(data: Uint8Array): Promise<void> {
    if (this.#terminated) return;
    const frames = this.#decoder.push(data);
    for (const frame of frames) {
      if (!this.#exchange.unwrapWithResult) throw transportError();
      const result = await this.#withContext(() => this.#exchange.unwrapWithResult!(frame));
      if (!validResult(result) || result.integrity !== true || this.#protection === "confidentiality" && result.confidential !== true) throw transportError();
      if (result.token.length > this.#maxInboundPlaintextBytes) throw transportError();
      if (!this.push(Buffer.from(result.token))) {
        this.#pausedForBackpressure = true;
        this.#native.pause();
        await new Promise<void>(resolve => { this.#readWaiter = resolve; });
      }
    }
  }
}
