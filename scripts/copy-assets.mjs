import { copyFile, mkdir } from 'node:fs/promises';

await mkdir('app/static/js', { recursive: true });
await mkdir('app/static/css', { recursive: true });
await mkdir('app/static/licenses', { recursive: true });
await copyFile('node_modules/htmx.org/dist/htmx.min.js', 'app/static/js/htmx.min.js');
await copyFile('node_modules/htmx.org/LICENSE', 'app/static/licenses/htmx.txt');
await copyFile('node_modules/tailwindcss/LICENSE', 'app/static/licenses/tailwindcss.txt');
await copyFile('assets/report.css', 'app/static/css/report.css');
