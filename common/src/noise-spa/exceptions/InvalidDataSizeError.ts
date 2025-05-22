export class InvalidDataSizeError extends Error {
  constructor(minimum: number, got: number) {
    super(`Data should be at least ${minimum} bytes, got ${got}`);
    this.name = "InvalidDataSizeError";
  }
}
