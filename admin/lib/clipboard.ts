export interface ClipboardWriter {
  writeText(text: string): Promise<void>;
}

// Whether the text was copied. Failures are reported by the result alone:
// what the clipboard throws is dropped, so the text cannot reach a log.
export async function copyText(
  clipboard: ClipboardWriter | undefined,
  text: string,
): Promise<boolean> {
  if (typeof clipboard?.writeText !== 'function') {
    return false;
  }
  try {
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
