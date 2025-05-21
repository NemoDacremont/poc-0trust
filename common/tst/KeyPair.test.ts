import { KeyPair } from "../src";
import { KEY_SIZE } from "../src/noise-spa/constants";

test("KeyPair.generate should generate KEY_SIZE long keys by default", () => {
  const keyPair = KeyPair.generate();

  expect(keyPair.getPublic().length).toBe(KEY_SIZE);
  expect(keyPair.getPrivate().length).toBe(KEY_SIZE);
});
