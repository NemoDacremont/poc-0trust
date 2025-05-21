export class InvalidKeySizeError extends Error {
  constructor(expected: number, got: number) {
    super(`Key should be exactly ${expected} bytes, got ${got}`);
    this.name = "InvalidKeySizeError";
  }
}
