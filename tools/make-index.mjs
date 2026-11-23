// Список готовых файлов data/wd/<id>.json для игры: data/wd/index.js → window.ORB_WD={id:"хеш"}.
// Хеш содержимого нужен, чтобы браузер не держал старую версию в кэше. Запуск: node tools/make-index.mjs
import {readdirSync,readFileSync,writeFileSync} from "node:fs";
import {createHash} from "node:crypto";
const dir=new URL("../data/wd/",import.meta.url);
const out={};
for(const f of readdirSync(dir).filter(f=>/^\d+\.json$/.test(f)).sort((a,b)=>parseInt(a)-parseInt(b))){
  const buf=readFileSync(new URL(f,dir));JSON.parse(buf);// битый файл — сразу ошибка
  out[parseInt(f)]=createHash("sha1").update(buf).digest("hex").slice(0,8);
}
writeFileSync(new URL("index.js",dir),"// создано tools/make-index.mjs — не править руками\nwindow.ORB_WD="+JSON.stringify(out)+";\n");
console.log("data/wd/index.js:",Object.keys(out).length,"файлов");
