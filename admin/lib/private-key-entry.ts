// The private-key input of the identity registration form (docs/design.md
// §9, §31.4). The key lives in the input and the form state until it is
// submitted, and after that only in the request body. JavaScript cannot
// erase strings, so this only limits what keeps a reference to it.

export interface PrivateKeyField {
  read(): string;
  clear(): void;
}

// Takes the key out of the field, clearing the field before the request is
// made and again once it has completed, whether it succeeded or not.
export async function submitPrivateKey<T>(
  field: PrivateKeyField,
  register: (privateKey: string) => Promise<T>,
): Promise<T> {
  const privateKey = field.read();
  field.clear();
  try {
    return await register(privateKey);
  } finally {
    field.clear();
  }
}

// Whether anything but whitespace has been entered, checked without making a
// copy of the input.
export function hasPrivateKeyInput(value: string): boolean {
  return /\S/.test(value);
}
