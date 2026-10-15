const app = require('./src/app');
const { port, build } = require('./src/config');

const server = app.listen(port, () => {
  console.log(JSON.stringify({ level: 'info', msg: 'CuraSecure portal started', port, build: build.buildNumber }));
});

// Graceful shutdown so Kubernetes rolling updates drop no requests
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
