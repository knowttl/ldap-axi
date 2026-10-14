// objectGUID binary <-> canonical "8-4-4-4-12" string. AD's on-wire byte order is mixed-endian:
// the first three fields are little-endian, the last two are big-endian (MS-DTYP 2.3.4.1). A
// straight hex dump of the 16 bytes does not match what AD tooling displays; this is the trap
// docs/design/v1.md §6.2 records.
export function decodeGuid(buffer: Buffer): string {
  if (buffer.length !== 16) throw new Error("GUID value must be exactly 16 bytes");
  const data1 = Buffer.from(buffer.subarray(0, 4)).reverse().toString("hex");
  const data2 = Buffer.from(buffer.subarray(4, 6)).reverse().toString("hex");
  const data3 = Buffer.from(buffer.subarray(6, 8)).reverse().toString("hex");
  const data4a = buffer.subarray(8, 10).toString("hex");
  const data4b = buffer.subarray(10, 16).toString("hex");
  return `${data1}-${data2}-${data3}-${data4a}-${data4b}`;
}

export function encodeGuid(guid: string): Buffer {
  const groups = guid.split("-");
  if (groups.length !== 5 || groups.some(group => !/^[0-9a-fA-F]+$/.test(group))) throw new Error("value is not an 8-4-4-4-12 GUID string");
  const [data1, data2, data3, data4a, data4b] = groups;
  return Buffer.concat([
    Buffer.from(data1, "hex").reverse(),
    Buffer.from(data2, "hex").reverse(),
    Buffer.from(data3, "hex").reverse(),
    Buffer.from(data4a, "hex"),
    Buffer.from(data4b, "hex"),
  ]);
}
