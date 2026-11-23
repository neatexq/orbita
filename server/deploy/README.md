# Сервер «Орбиты»

Сайт: https://orbita.129-151-216-221.sslip.io (Oracle Cloud, Ubuntu, Caddy). Старый адрес на GitHub Pages перекидывает сюда и переносит сохранения игрока.

- **Статика** — Caddy отдаёт `/opt/orbita` (клон этого репозитория). Блок `orbita.…` в `/etc/caddy/Caddyfile`, файл `Caddyfile.orbita` здесь.
- **API** — `server/server.mjs` (Node 24, без зависимостей, SQLite встроенный): проверка ответов нейросетью (Groq) с кэшем, админка для `tools/review.html`, дуэли с живыми обновлениями (SSE). Служба `orbita.service`, слушает `127.0.0.1:8790`, база `/var/lib/orbita/orbita.db`.
- **Секреты** — `/etc/orbita/env` (только root): `LLM_KEY`, `ADMIN_TOKEN`. В репозитории их нет.
- **Обновление** — `orbita-sync.timer` раз в минуту делает `git fetch` и обновляет `/opt/orbita`; если менялся `server/`, перезапускает API. То есть достаточно запушить в `main`.

Полезное:

```
sudo systemctl status orbita            # состояние API
sudo journalctl -u orbita -n 50         # логи API
sudo journalctl -u orbita-sync -n 20    # что подтянулось с GitHub
sudo systemctl start orbita-sync        # подтянуть прямо сейчас
```
