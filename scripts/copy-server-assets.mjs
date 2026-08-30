import fs from 'node:fs';
import path from 'node:path';

const source = path.resolve('server/migrations');
const destination = path.resolve('dist/local-server/migrations');

fs.mkdirSync(destination, { recursive: true });
for (const name of fs.readdirSync(source)) {
  fs.copyFileSync(path.join(source, name), path.join(destination, name));
}
