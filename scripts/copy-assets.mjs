import { copyFile, mkdir } from 'node:fs/promises';

await mkdir('app/static/js', { recursive: true });
await mkdir('app/static/css', { recursive: true });
await mkdir('app/static/fonts', { recursive: true });
await mkdir('app/static/licenses', { recursive: true });
await copyFile('node_modules/htmx.org/dist/htmx.min.js', 'app/static/js/htmx.min.js');
await copyFile('node_modules/htmx.org/LICENSE', 'app/static/licenses/htmx.txt');
await copyFile('node_modules/tailwindcss/LICENSE', 'app/static/licenses/tailwindcss.txt');

// IBM Plex, Latin subset: the weights the interface uses (the @font-face rules are in assets/app.css).
const faces = { 'ibm-plex-sans': [400, 500, 600], 'ibm-plex-mono': [400, 600] };
for (const [family, weights] of Object.entries(faces)) {
  for (const weight of weights) {
    const file = `${family}-latin-${weight}-normal.woff2`;
    await copyFile(`node_modules/@fontsource/${family}/files/${file}`, `app/static/fonts/${file}`);
  }
  await copyFile(`node_modules/@fontsource/${family}/LICENSE`, `app/static/licenses/${family}.txt`);
}

await copyFile('assets/report.css', 'app/static/css/report.css');
