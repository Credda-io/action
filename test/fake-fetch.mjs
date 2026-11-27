// Test only: `node --import ./test/fake-fetch.mjs integrate.mjs ...` sends every
// request to the local server in CREDDA_TEST_ORIGIN instead of the real host, and
// says which host was meant in an `x-meant-host` header. integrate.mjs never loads
// this file, so a real run has no way to redirect a request.

const origin = process.env.CREDDA_TEST_ORIGIN;
const real = globalThis.fetch;

globalThis.fetch = (url, init = {}) => {
  const meant = new URL(url);
  const local = new URL(`${meant.pathname}${meant.search}`, origin);
  return real(local, { ...init, headers: { ...init.headers, 'x-meant-host': meant.host } });
};
