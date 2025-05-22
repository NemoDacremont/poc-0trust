export class InvalidNVSizeError extends Error {
  constructor(expected: number, got: number) {
    super(`NV should be exactly ${expected} bytes, got ${got}`);
    this.name = "InvalidNVSizeError";
  }
}
