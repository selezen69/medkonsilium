import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { createApp } from './server.mjs';
const rl = createInterface({ input: stdin, output: stdout });
const app = createApp();
try {
  const name = await rl.question('Имя администратора: ');
  const email = await rl.question('Email: ');
  // Read a password without echoing it. Browser setup is also available with a one-time bootstrap token.
  if (!stdin.isTTY) throw new Error('Запустите настройку в интерактивном терминале.');
  stdout.write('Пароль (не менее 6 символов; ввод скрыт): ');
  rl.close(); stdin.setRawMode(true); stdin.resume();
  const password = await new Promise((resolve, reject) => {
    let value = '';
    const listener = chunk => {
      const s = chunk.toString();
      if (s === '\r' || s === '\n') { stdin.off('data', listener); resolve(value); }
      else if (s === '\u0003') { stdin.off('data', listener); reject(new Error('Отменено.')); }
      else if (s === '\u007f') value = value.slice(0,-1);
      else if (!/[\x00-\x1f]/.test(s)) value += s;
    };
    stdin.on('data', listener);
  });
  stdin.setRawMode(false); stdin.pause(); stdout.write('\n');
  await app.addAdmin(email, password, name);
  console.log('Администратор создан. Запустите npm start.');
} catch (e) { console.error(e.message); process.exitCode = 1; }
finally { if (stdin.isTTY) stdin.setRawMode(false); rl.close(); await app.close(); }
