/** Strip HTML tags and control chars from user text. Clients must STILL output-encode when rendering. */
export const clean = (s: string) => s.replace(/<[^>]*>/g, '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
export function cleanStrings<T extends Record<string, unknown>>(o: T): T {
  const out: Record<string, unknown> = { ...o };
  for (const k of Object.keys(out)) if (typeof out[k] === 'string') out[k] = clean(out[k] as string);
  return out as T;
}
