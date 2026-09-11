// The decisions behind telling a webhook what a run found.
//
// WHY THIS FILE IS SEPARATE FROM THE SCRIPT THAT POSTS. The same split as
// `delivery.mjs` and `deliver-pr.mjs`, for the same reason: everything here is
// a pure function of values -- whether there is anything to say, what the body
// is, and what one failure is called -- plus one bounded POST whose `fetch` is
// handed in. `notify.mjs` is the half that reads a runner's environment. This
// half can be tested with no network and no runner, by `.github/notify.test.mjs`.
//
// WHY THE ACTION SENDS THIS AND NOT THE BACKEND. Credda's backend never
// receives a run's facts: metering carries salted HMACs of the owner, the
// repository and the actor, an outcome token and a version, and nothing else
// (see `metering-url` in action.yml). So there is no server that could post
// "Credda found N things in owner/repo" to a customer's Slack, and building
// one would mean first sending it the things it has been promised it never
// sees. The honest place for an outbound notification is here, on the
// customer's runner, to an address the customer typed, carrying facts that
// are already in the job's own outputs.
//
// WHAT IS NOT DECIDED HERE. Whether a run established anything or stated a
// finding. Both arrive as this action's own outputs -- `established` is the
// engine's `establishedSomething`, `stated-findings` is the count of rows the
// repository itself settled -- and this file reads them and never re-derives
// them, for the reason `delivery.mjs` gives: two opinions about one run is how
// a surface comes to claim something the report denies.

/**
 * Whether there is anything to notify about, and why not when there is not.
 *
 * A run that established nothing and stated nothing sends nothing, whatever
 * the URL says. A channel that receives "Credda ran" on every push is a channel
 * that gets muted, and the report already leads with what could NOT be
 * established -- that document is about Credda, and a webhook is not where it
 * belongs.
 *
 * @param {{ url: string, statedFindings: number, established: boolean }} input
 * @returns {{ notify: boolean, reason: string }}
 */
export function decideNotification({ url, statedFindings, established }) {
  if (url === '') {
    return { notify: false, reason: 'notify-url is empty, which is the default. No request was made.' };
  }
  if (statedFindings > 0 || established) {
    return { notify: true, reason: 'the run established something or stated a finding.' };
  }
  return {
    notify: false,
    reason:
      'the run established nothing and stated no finding, so no notification was sent. The ' +
      'report is on the job summary; a webhook is not where a run that found nothing belongs.',
  };
}

/**
 * The facts a notification carries. Every one of them is already a published
 * output of this action or a runner-provided variable; nothing here is read
 * out of the report itself, so the body cannot carry issue text, code or paths.
 *
 * @typedef {object} Facts
 * @property {string} investigationId  '' in discover and triage mode
 * @property {string} repository       owner/repo
 * @property {string} outcome          '' outside investigate mode
 * @property {number} statedFindings   0 outside discover mode
 * @property {boolean} established
 * @property {string|null} reportUrl   the run's URL on the forge, or null
 * @property {string} actionVersion    e.g. v0.1.1
 */

/**
 * The JSON body a generic endpoint receives.
 *
 * @param {Facts} facts
 * @returns {Record<string, unknown>}
 */
export function notificationBody(facts) {
  return {
    investigationId: facts.investigationId,
    repository: facts.repository,
    outcome: facts.outcome,
    statedFindings: facts.statedFindings,
    established: facts.established,
    reportUrl: facts.reportUrl,
    actionVersion: facts.actionVersion,
  };
}

/**
 * The same facts as one plain sentence, for an incoming webhook that renders
 * `text` and nothing else. Every value is one this action produced or GitHub
 * provided, and none of it is a reporter's words.
 *
 * @param {Facts} facts
 * @returns {string}
 */
export function notificationSentence(facts) {
  const what =
    facts.statedFindings > 0
      ? `stated ${String(facts.statedFindings)} finding${facts.statedFindings === 1 ? '' : 's'}`
      : `reached ${facts.outcome === '' ? 'an established result' : facts.outcome}`;
  const id = facts.investigationId === '' ? '' : ` (investigation ${facts.investigationId})`;
  const where = facts.reportUrl === null ? '' : `: ${facts.reportUrl}`;
  return `Credda ${facts.actionVersion} ${what} in ${facts.repository}${id}${where}`;
}

/**
 * Whether a URL is Slack's incoming-webhook host, which accepts `{text}` and
 * rejects any other shape with a 400. Matched on the host exactly, so a
 * customer's own endpoint that happens to mention Slack in its path gets the
 * full body.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function isSlackWebhook(url) {
  try {
    return new URL(url).host === 'hooks.slack.com';
  } catch {
    return false;
  }
}

/**
 * Sends one notification, and can never throw.
 *
 * The rule is the one `meter()` in run.mjs states: no line here can end a
 * customer's job, and the only way to have that structurally is for the whole
 * body to be inside a `catch` that returns. One request, no retry, bounded by
 * `timeoutMs`. What comes back is one line for the log: what was sent and to
 * where, or the status or error that stopped it.
 *
 * @param {{ url: string, facts: Facts, fetch: typeof globalThis.fetch, timeoutMs?: number }} input
 * @returns {Promise<{ sent: boolean, line: string }>}
 */
export async function sendNotification({ url, facts, fetch, timeoutMs = 10_000 }) {
  const slack = isSlackWebhook(url);
  const body = slack ? { text: notificationSentence(facts) } : notificationBody(facts);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      return {
        sent: false,
        line: `Notification was not delivered: ${url} answered ${String(response.status)}. This run is unaffected.`,
      };
    }
    return {
      sent: true,
      line: `Notification sent to ${url}${slack ? ' as Slack text' : ''}.`,
    };
  } catch (error) {
    const said = error instanceof Error ? error.message : String(error);
    return { sent: false, line: `Notification was not delivered: ${said}. This run is unaffected.` };
  }
}
