export default {
  async fetch(request) {
    return new Response('OK - placeholder worker', { status: 200 });
  },
};
