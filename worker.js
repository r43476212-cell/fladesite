
const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });

const enc = (s) => new TextEncoder().encode(s);

function b64u(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function unb64u(value) {
  const s = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", enc(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return b64u(await crypto.subtle.sign("HMAC", key, enc(data)));
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", enc(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc(salt), iterations: 210000, hash: "SHA-256" },
    key,
    256
  );
  return b64u(bits);
}

async function sessionToken(env, user) {
  if (!env.SESSION_SECRET) throw new Error("SESSION_SECRET is missing");
  const payload = b64u(enc(JSON.stringify({
    sub: user.id,
    username: user.username,
    role: user.role,
    exp: Date.now() + 8 * 60 * 60 * 1000,
  })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

async function currentUser(req, env) {
  const raw = (req.headers.get("Cookie") || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("flade_session="))
    ?.slice("flade_session=".length);

  if (!raw || !env.SESSION_SECRET) return null;

  const dot = raw.lastIndexOf(".");
  if (dot < 1) return null;

  const payload = raw.slice(0, dot);
  const signature = raw.slice(dot + 1);

  if (await hmac(env.SESSION_SECRET, payload) !== signature) return null;

  try {
    const user = JSON.parse(new TextDecoder().decode(unb64u(payload)));
    if (!user.sub || !user.username || user.exp < Date.now()) return null;

    // Confirm the account still exists and its role has not changed.
    const account = await env.DB.prepare(
      "SELECT id, username, role FROM users WHERE id = ?"
    ).bind(user.sub).first();

    if (!account) return null;
    return { sub: account.id, username: account.username, role: account.role };
  } catch {
    return null;
  }
}

const cookie = (value, maxAge) =>
  `flade_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

const badCookie =
  "flade_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

function safeImages(raw, fallback) {
  try {
    const parsed = JSON.parse(raw || "[]");
    const images = Array.isArray(parsed)
      ? parsed.filter((x) => typeof x === "string").slice(0, 8)
      : [];
    if (fallback && !images.includes(fallback)) images.unshift(fallback);
    return images;
  } catch {
    return fallback ? [fallback] : [];
  }
}

function validProduct(p) {
  return p &&
    String(p.title || "").trim() &&
    String(p.sizes || "").trim() &&
    String(p.description || "").trim() &&
    String(p.image || "").trim() &&
    Number.isInteger(Number(p.price)) &&
    Number(p.price) >= 0 &&
    Number(p.price) <= 10000000;
}

function normalizeProduct(p) {
  const image = String(p.image).trim().slice(0, 1000);
  const images = Array.isArray(p.images)
    ? p.images.filter((x) => typeof x === "string").slice(0, 8)
    : [];

  if (!images.includes(image)) images.unshift(image);

  return {
    title: String(p.title).trim().slice(0, 120),
    price: Number(p.price),
    sizes: String(p.sizes).trim().slice(0, 120),
    description: String(p.description).trim().slice(0, 1200),
    image,
    images: JSON.stringify(images),
    visible: p.visible === false || p.visible === 0 || p.visible === "0" ? 0 : 1,
  };
}

async function requireUser(req, env) {
  const user = await currentUser(req, env);
  return user;
}

async function api(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;

  try {
    if (path === "/api/health" && req.method === "GET") {
      return json({ ok: true });
    }

    // Initial owner setup. Configure BOOTSTRAP_SECRET before using this route.
    // This endpoint works only while the users table is empty.
    if (path === "/api/setup-owner" && req.method === "POST") {
      if (!env.BOOTSTRAP_SECRET) {
        return json({ error: "Первоначальная настройка не включена" }, 403);
      }

      const supplied = req.headers.get("Authorization") || "";
      const expected = `Bearer ${env.BOOTSTRAP_SECRET}`;

      if (supplied.length !== expected.length) {
        return json({ error: "Доступ запрещён" }, 403);
      }

      let matches = true;
      for (let i = 0; i < supplied.length; i++) {
        if (supplied.charCodeAt(i) !== expected.charCodeAt(i)) matches = false;
      }
      if (!matches) return json({ error: "Доступ запрещён" }, 403);

      const count = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM users"
      ).first();

      if (Number(count?.n) !== 0) {
        return json({ error: "Первоначальная настройка уже завершена" }, 409);
      }

      const body = await req.json();
      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      if (!/^[A-Za-zА-Яа-яЁё0-9_-]{3,32}$/.test(username)) {
        return json({ error: "Логин: 3–32 символа, буквы, цифры, _ или -" }, 400);
      }
      if (password.length < 12 || password.length > 200) {
        return json({ error: "Пароль должен содержать от 12 до 200 символов" }, 400);
      }

      const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
      const hash = await hashPassword(password, salt);
      const id = crypto.randomUUID();

      // Conditional insert prevents a second setup after the first owner exists.
      const result = await env.DB.prepare(`
        INSERT INTO users (id, username, password_hash, password_salt, role)
        SELECT ?, ?, ?, ?, 'owner'
        WHERE NOT EXISTS (SELECT 1 FROM users)
      `).bind(id, username, hash, salt).run();

      if (!result.success || Number(result.meta?.changes || 0) !== 1) {
        return json({ error: "Первоначальная настройка уже завершена" }, 409);
      }

      return json({ ok: true, id, username, role: "owner" }, 201);
    }

    if (path === "/api/login" && req.method === "POST") {
      const body = await req.json();
      const username = String(body.username || "").trim();
      const user = await env.DB.prepare(
        "SELECT id, username, password_hash, password_salt, role FROM users WHERE username = ?"
      ).bind(username).first();

      if (!user || await hashPassword(String(body.password || ""), user.password_salt) !== user.password_hash) {
        return json({ error: "Логин или пароль неверны" }, 401);
      }

      const token = await sessionToken(env, user);
      return json(
        { ok: true, username: user.username, role: user.role },
        200,
        { "set-cookie": cookie(token, 28800) }
      );
    }

    if (path === "/api/logout" && req.method === "POST") {
      return json({ ok: true }, 200, { "set-cookie": badCookie });
    }

    if (path === "/api/me" && req.method === "GET") {
      const user = await requireUser(req, env);
      return user
        ? json({ ok: true, id: user.sub, username: user.username, role: user.role })
        : json({ error: "Требуется вход" }, 401);
    }

    if (path === "/api/products" && req.method === "GET") {
      const user = await currentUser(req, env);
      const all = url.searchParams.get("all") === "1" && !!user;

      const result = all
        ? await env.DB.prepare("SELECT * FROM products ORDER BY created_at DESC").all()
        : await env.DB.prepare("SELECT * FROM products WHERE visible = 1 ORDER BY created_at DESC").all();

      return json({
        products: (result.results || []).map((p) => ({
          ...p,
          visible: !!p.visible,
          images: safeImages(p.images, p.image),
        })),
      });
    }

    if (path === "/api/upload" && req.method === "POST") {
      const user = await requireUser(req, env);
      if (!user) return json({ error: "Требуется вход" }, 401);

      const form = await req.formData();
      const file = form.get("file") || form.get("image");

      if (!(file instanceof File)) {
        return json({ error: "Выбери файл изображения" }, 400);
      }

      const allowed = ["image/jpeg", "image/png", "image/webp"];
      if (!allowed.includes(file.type)) {
        return json({ error: "Поддерживаются JPG, PNG и WebP" }, 400);
      }

      const maxBytes = 400 * 1024;
      if (file.size < 1 || file.size > maxBytes) {
        return json({ error: "Размер изображения должен быть не более 400 КБ" }, 400);
      }

      const id = crypto.randomUUID();
      const data = b64u(await file.arrayBuffer());

      await env.DB.prepare(
        "INSERT INTO product_images (id, mime_type, image_data) VALUES (?, ?, ?)"
      ).bind(id, file.type, data).run();

      const imageUrl = `/media/${id}`;
      return json({ ok: true, url: imageUrl, image: imageUrl }, 201);
    }

    if (path.startsWith("/api/users")) {
      const user = await requireUser(req, env);
      if (!user) return json({ error: "Требуется вход" }, 401);
      if (user.role !== "owner") {
        return json({ error: "Только владелец может управлять аккаунтами" }, 403);
      }

      if (path === "/api/users" && req.method === "GET") {
        const r = await env.DB.prepare(
          "SELECT id, username, role, created_at FROM users ORDER BY created_at"
        ).all();
        return json({ users: r.results || [] });
      }

      if (path === "/api/users" && req.method === "POST") {
        const body = await req.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const role = body.role === "owner" ? "owner" : "admin";

        if (!/^[A-Za-zА-Яа-яЁё0-9_-]{3,32}$/.test(username)) {
          return json({ error: "Логин: 3–32 символа, буквы, цифры, _ или -" }, 400);
        }
        if (password.length < 12 || password.length > 200) {
          return json({ error: "Пароль должен содержать от 12 до 200 символов" }, 400);
        }

        const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
        if (Number(count?.n) >= 3) {
          return json({ error: "В этой версии разрешено максимум 3 аккаунта" }, 400);
        }

        const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
        const hash = await hashPassword(password, salt);
        const id = crypto.randomUUID();

        try {
          await env.DB.prepare(
            "INSERT INTO users (id, username, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)"
          ).bind(id, username, hash, salt, role).run();
        } catch {
          return json({ error: "Такой логин уже существует" }, 409);
        }

        return json({ ok: true, id }, 201);
      }

      const id = path.split("/")[3];
      if (id && req.method === "DELETE") {
        if (id === user.sub) {
          return json({ error: "Нельзя удалить свой аккаунт во время входа" }, 400);
        }

        const target = await env.DB.prepare(
          "SELECT role FROM users WHERE id = ?"
        ).bind(id).first();

        if (!target) return json({ error: "Аккаунт не найден" }, 404);

        if (target.role === "owner") {
          const owners = await env.DB.prepare(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'owner'"
          ).first();

          if (Number(owners?.n) <= 1) {
            return json({ error: "Нельзя удалить последнего владельца" }, 400);
          }
        }

        await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
        return json({ ok: true });
      }

      return json({ error: "Не найдено" }, 404);
    }

    if (path === "/api/products" && req.method === "POST") {
      const user = await requireUser(req, env);
      if (!user) return json({ error: "Требуется вход" }, 401);

      const p = await req.json();
      if (!validProduct(p)) {
        return json({ error: "Проверь название, цену, размеры, описание и фото" }, 400);
      }

      const n = normalizeProduct(p);
      const id = crypto.randomUUID();

      await env.DB.prepare(`
        INSERT INTO products (id, title, price, sizes, description, image, images, visible)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(id, n.title, n.price, n.sizes, n.description, n.image, n.images, n.visible).run();

      return json({ ok: true, id }, 201);
    }

    if (path.startsWith("/api/products/")) {
      const user = await requireUser(req, env);
      if (!user) return json({ error: "Требуется вход" }, 401);

      const id = path.slice("/api/products/".length);

      if (req.method === "PUT") {
        const p = await req.json();
        if (!validProduct(p)) return json({ error: "Проверь поля товара" }, 400);

        const n = normalizeProduct(p);
        const result = await env.DB.prepare(`
          UPDATE products
          SET title = ?, price = ?, sizes = ?, description = ?, image = ?, images = ?,
              visible = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(n.title, n.price, n.sizes, n.description, n.image, n.images, n.visible, id).run();

        if (Number(result.meta?.changes || 0) === 0) {
          return json({ error: "Товар не найден" }, 404);
        }

        return json({ ok: true });
      }

      if (req.method === "DELETE") {
        const product = await env.DB.prepare(
          "SELECT image, images FROM products WHERE id = ?"
        ).bind(id).first();

        if (!product) return json({ error: "Товар не найден" }, 404);

        // Remove D1-stored image records referenced by this product.
        const images = safeImages(product.images, product.image);
        for (const image of images) {
          const match = image.match(/^\/media\/([0-9a-f-]{36})$/i);
          if (match) {
            await env.DB.prepare("DELETE FROM product_images WHERE id = ?")
              .bind(match[1]).run();
          }
        }

        await env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
        return json({ ok: true });
      }
    }

    return json({ error: "Не найдено" }, 404);
  } catch (error) {
    console.error("FLADE worker error:", error?.message || error);
    return json({ error: "Внутренняя ошибка сервера" }, 500);
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname.startsWith("/api/")) return api(req, env);

    if (url.pathname.startsWith("/media/")) {
      const id = url.pathname.slice("/media/".length);
      if (!/^[0-9a-f-]{36}$/i.test(id)) {
        return new Response("Not found", { status: 404 });
      }

      try {
        const image = await env.DB.prepare(
          "SELECT mime_type, image_data FROM product_images WHERE id = ?"
        ).bind(id).first();

        if (!image) return new Response("Not found", { status: 404 });

        return new Response(unb64u(image.image_data), {
          headers: {
            "content-type": image.mime_type,
            "cache-control": "public, max-age=86400",
            "x-content-type-options": "nosniff",
          },
        });
      } catch (error) {
        console.error("FLADE image error:", error?.message || error);
        return new Response("Image unavailable", { status: 500 });
      }
    }

    if (url.pathname === "/admin") {
      return Response.redirect(new URL("/admin/", url), 302);
    }

    return env.ASSETS.fetch(req);
  },
};
