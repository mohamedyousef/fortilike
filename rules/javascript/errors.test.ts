interface Res {
  status(code: number): { send(body: unknown): void };
  end(body: string): void;
}

export function handle(res: Res, work: Promise<void>): void {
  // ruleid: fortify.poor-error-handling-empty-catch-block
  try { JSON.parse('x'); } catch (e) { }
  // ruleid: fortify.poor-error-handling-empty-catch-block
  try { JSON.parse('x'); } catch { }
  // ok: fortify.poor-error-handling-empty-catch-block
  try { JSON.parse('x'); } catch { return; }
  // ruleid: fortify.poor-error-handling-empty-catch-block
  work.catch(() => {});
  // ok: fortify.poor-error-handling-empty-catch-block
  work.catch((error) => console.warn('background work failed', error.message));

  try {
    JSON.parse('y');
  } catch (err) {
    // ruleid: fortify.system-information-leak-external
    res.status(500).send(err.stack);
    // ruleid: fortify.system-information-leak-external
    res.end(err.message);
    // ok: fortify.system-information-leak-external
    res.end('Something went wrong');
    // ruleid: fortify.system-information-leak-internal
    console.error(err.stack);
    // ok: fortify.system-information-leak-internal
    console.error(err.message);
  }
}
