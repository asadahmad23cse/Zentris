## Nginx Reverse Proxy

Active runtime template:
- `templates/default.conf.template` (HTTP reverse proxy + security headers)

Future SSL template:
- `examples/default-ssl.conf.template`

To enable SSL with Let's Encrypt later:
1. Copy `examples/default-ssl.conf.template` to `templates/default.conf.template`.
2. Mount cert files into `docker/nginx/ssl/`:
   - `fullchain.pem`
   - `privkey.pem`
3. Set `NGINX_SERVER_NAME` in `.env` (for example: `api.example.com`).
4. Restart nginx service.
