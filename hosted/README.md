# Hosted prototype

`node hosted/build.mjs <site-checkout>` builds a dependency-free Cloudflare Worker from `ai.mjs`, `public/`, and `hosted/worker/api.mjs`. It copies migrations into the target checkout. The Site manifest must retain its project ID, omit `static`, and declare `d1: "DB"`, `r2: "BUCKET"`.

The hosted version uses Sites ChatGPT identity headers, not the Node version's password sessions. `OWNER_EMAIL` is a server-side secret specifying the owner allowed to initialize the first profile. Sharing the Site alone does not create app membership. Missing identities, non-owner accounts, foreign profile IDs, invalid Origin and CSRF tokens are rejected server-side.

D1 stores questions, messages, metadata, confirmed document text and run results. R2 stores original files under private keys. No original file has a public URL. Do not copy local trial databases or `.env` to the Site.

Current deployed scope: owner profile, questions, follow-ups, 12 role cards, 1–4 specialist selections, PDF/PNG/JPEG uploads, original download and manual text confirmation. Family invitations, OCR, voice, backup controls, history import and user deletion are not implemented in this hosted prototype. Family screen states this explicitly.

AI requires both OPENAI_API_KEY and OPENAI_MODEL. Neither is configured by this change. No demonstration medical answers are substituted. The adapter runs within the request instead of relying on short-lived background tasks; long or interrupted requests may require retry and stale runs are marked interrupted. Real paid API behavior is not verified.

`node --test test/hosted.test.mjs` validates the API against a local SQLite D1 adapter and in-memory R2 adapter using fictitious data. The published private Site's post-login flow still needs manual verification; browser authorization to the external ChatGPT authentication origin was denied by automatic review.
