/*
 * What `notify-url` sends, when it stays quiet, and that it cannot fail a job.
 *
 * WHY THIS ONE LIVES HERE. The tests that hold `run.mjs`, `delivery.mjs` and
 * `action.yml` to their meanings are in the private engine checkout, which
 * reads this repository as a sibling (see the header of `delivery.mjs`). They
 * were put there because this repository will not carry a test runner's
 * `node_modules`. `notification.mjs` needs none: it is a pure function of
 * values plus a POST whose `fetch` is handed in, and `node --test` is Node's
 * own runner. So the assertions sit beside the file they are about, and
 * `ci.yml` runs them on every pull request with nothing installed.
 *
 * What is NOT asserted here: that a real Slack webhook accepts the sentence.
 * That needs a channel, and nothing on a pull request has one.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  decideNotification,
  isSlackWebhook,
  notificationBody,
  notificationSentence,
  sendNotification,
} from '../notification.mjs';

const facts = {
  investigationId: 'inv_123',
  repository: 'acme/widgets',
  outcome: 'REPRODUCED_AND_DIAGNOSED',
  statedFindings: 0,
  established: true,
  reportUrl: 'https://github.com/acme/widgets/actions/runs/42',
  actionVersion: 'v0.1.1',
};

/** A fetch that records what it was given and answers as told. */
function fakeFetch(answer) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (answer instanceof Error) throw answer;
    return { ok: answer >= 200 && answer < 300, status: answer };
  };
  return { fetch, calls };
}

describe('decideNotification', () => {
  it('says nothing to send when notify-url is empty', () => {
    const decision = decideNotification({ url: '', statedFindings: 3, established: true });
    assert.equal(decision.notify, false);
    assert.match(decision.reason, /notify-url is empty/);
  });

  it('sends nothing for a run that established nothing and stated no finding', () => {
    const decision = decideNotification({
      url: 'https://example.test/hook',
      statedFindings: 0,
      established: false,
    });
    assert.equal(decision.notify, false);
    assert.match(decision.reason, /established nothing and stated no finding/);
  });

  it('notifies on a stated finding or an established result', () => {
    assert.equal(
      decideNotification({ url: 'https://example.test/hook', statedFindings: 1, established: false }).notify,
      true,
    );
    assert.equal(
      decideNotification({ url: 'https://example.test/hook', statedFindings: 0, established: true }).notify,
      true,
    );
  });
});

describe('the payload', () => {
  it('carries exactly the seven documented fields and nothing from the report', () => {
    const body = notificationBody(facts);
    assert.deepEqual(Object.keys(body).sort(), [
      'actionVersion',
      'established',
      'investigationId',
      'outcome',
      'reportUrl',
      'repository',
      'statedFindings',
    ]);
    assert.deepEqual(body, {
      investigationId: 'inv_123',
      repository: 'acme/widgets',
      outcome: 'REPRODUCED_AND_DIAGNOSED',
      statedFindings: 0,
      established: true,
      reportUrl: 'https://github.com/acme/widgets/actions/runs/42',
      actionVersion: 'v0.1.1',
    });
  });

  it('is POSTed as JSON to the URL given, with a bounded signal', async () => {
    const { fetch, calls } = fakeFetch(200);
    const result = await sendNotification({ url: 'https://example.test/hook', facts, fetch });
    assert.equal(result.sent, true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://example.test/hook');
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.headers['content-type'], 'application/json');
    assert.ok(calls[0].init.signal instanceof AbortSignal);
    assert.deepEqual(JSON.parse(calls[0].init.body), notificationBody(facts));
  });

  it('carries a null reportUrl when the runner did not say which run this is', () => {
    assert.equal(notificationBody({ ...facts, reportUrl: null }).reportUrl, null);
  });
});

describe('the Slack variant', () => {
  it('recognises hooks.slack.com by host and nothing else', () => {
    assert.equal(isSlackWebhook('https://hooks.slack.com/services/T0/B0/x'), true);
    assert.equal(isSlackWebhook('https://example.test/hooks.slack.com'), false);
    assert.equal(isSlackWebhook('not a url'), false);
  });

  it('sends {text} carrying the same facts in one sentence', async () => {
    const { fetch, calls } = fakeFetch(200);
    const result = await sendNotification({
      url: 'https://hooks.slack.com/services/T0/B0/x',
      facts,
      fetch,
    });
    assert.equal(result.sent, true);
    const body = JSON.parse(calls[0].init.body);
    assert.deepEqual(Object.keys(body), ['text']);
    assert.equal(body.text, notificationSentence(facts));
    for (const fact of ['v0.1.1', 'REPRODUCED_AND_DIAGNOSED', 'acme/widgets', 'inv_123', facts.reportUrl]) {
      assert.ok(body.text.includes(fact), `sentence names ${fact}`);
    }
    assert.equal(body.text.split('\n').length, 1);
  });

  it('names the count in discover mode', () => {
    const sentence = notificationSentence({ ...facts, investigationId: '', outcome: '', statedFindings: 2 });
    assert.match(sentence, /stated 2 findings in acme\/widgets/);
    assert.doesNotMatch(sentence, /investigation/);
  });
});

describe('a failed POST', () => {
  it('names the status and does not throw', async () => {
    const { fetch } = fakeFetch(500);
    const result = await sendNotification({ url: 'https://example.test/hook', facts, fetch });
    assert.equal(result.sent, false);
    assert.match(result.line, /answered 500/);
    assert.match(result.line, /This run is unaffected/);
  });

  it('names the error and does not throw', async () => {
    const { fetch } = fakeFetch(new Error('ECONNREFUSED'));
    const result = await sendNotification({ url: 'https://example.test/hook', facts, fetch });
    assert.equal(result.sent, false);
    assert.match(result.line, /ECONNREFUSED/);
  });
});
