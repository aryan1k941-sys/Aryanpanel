# ARYAN Reseller Panel (Flask)

A mobile-friendly starter reseller panel based on the supplied `admin.html` and `user.html` files. The original uploads are preserved in `reference/` for comparison. The running app uses a new Flask UI and SQLite backend because the originals depend on Firebase/browser-side code and are not directly wired to a secure Flask API.

## Features
- User registration/login and server-side password hashing.
- Admin account bootstrapped only from `ADMIN_EMAIL` and `ADMIN_PASSWORD` environment variables.
- Admin dashboard for provider URL/key, FamGateway key, UPI ID, service pricing, users, balances, payments and orders.
- Server-side provider API calls (secrets are never sent to browser JS).
- Wallet ledger, server-calculated order prices and FamGateway top-up checkout.
- FamGateway webhook HMAC-SHA256 validation and server-to-server status verification before wallet credit.
- Responsive dark/neon interface and loading feedback.

## Run locally (Android Termux or computer)
```bash
python -m venv .venv
# Activate the environment, then:
pip install -r requirements.txt
cp .env.example .env
```
Set environment variables from `.env` in your shell or hosting dashboard. This starter does not automatically load `.env`; use your host's Environment Variables, or install `python-dotenv` and add `from dotenv import load_dotenv; load_dotenv()` before creating the Flask app.
Then:
```bash
python app.py
```
Open `http://127.0.0.1:5000`.

## Render
- Upload the project to a private GitHub repository.
- Create a Render Web Service.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Set `SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `COOKIE_SECURE=1`.
- Add a persistent disk and set `DATABASE_PATH` to a path on that disk if you want SQLite data to survive redeploys. Without persistent storage, a local SQLite database may be lost.
- Use HTTPS in production and never commit real API keys.

## First admin login
At first boot, if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set, the app creates the admin account. Do not use a weak password. To rotate the admin password, update it through a controlled database/admin process; changing the environment variable does not overwrite an existing account.

## Provider API: exact documentation is required
The custom provider adapter is intentionally generic:
- Service test: `GET {provider_api_url}/{provider_services_path}`
- Submit order: `POST {provider_api_url}/{provider_order_path}`
- Auth headers sent: `X-Api-Key` and `Authorization: Bearer ...`
- Order JSON sent: `{"service": "<provider service id>", "link": "<target>", "quantity": <int>}`
- It expects JSON and looks for `order` or `order_id` in an object response.

These are conventions, NOT guaranteed to match your provider. To make it truly work, supply the provider's API documentation (base URL, authentication method/header, list-services endpoint and sample response, create-order endpoint and required fields/sample response, order-status endpoint). Then adapt `provider_request()` and the order payload/status mapping in `app.py`.

## FamGateway
The integration follows the public FamGateway docs at https://famgateway.in/docs.php:
- Creates checkout with `POST https://famgateway.in/api/create-order` and `X-Api-Key`.
- Uses the returned `checkout_url` and `order_id`.
- Verifies signed webhook HMAC-SHA256 using the configured FamGateway API key.
- Calls `GET https://famgateway.in/api/verify-order.php?order_id=...` from the server before crediting.
- Wallet credit is idempotent per local payment row.

Before production, test with small amounts and confirm the exact response envelope/status field from your merchant account. Never credit balance just because the browser returns to the site. Ensure your FamGateway account is configured to call `https://YOUR-DOMAIN/api/fam-webhook`.

## Important production hardening
This is a starter, not a fully audited production commerce platform. Before taking real money:
- Add CSRF protection and rate limiting.
- Use a managed database (PostgreSQL) for production/multiple instances.
- Add provider order-status polling and an idempotent cancellation/refund policy.
- Review provider terms, product/service legality, privacy policy and refund policy.
- Add admin password change/reset and audit logs.
- Never run untrusted code from users or expose secrets in frontend pages.
