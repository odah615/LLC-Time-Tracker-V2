import worker from '../../src/server/apiHandler.js';

export async function onRequest(context) {
  return worker.fetch(context.request, context.env, context);
}
