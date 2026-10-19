
const $ = (selector) => document.querySelector(selector);

const loginPanel = $("#loginPanel");
const appPanel = $("#appPanel");
const loginMessage = $("#loginMessage");
const productMessage = $("#productMessage");
const form = $("#productForm");

let me = null;
let loadingProducts = false;

async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };

    if (opts.body && typeof opts.body === "string") {
        headers["Content-Type"] = "application/json";
    }

    const res = await fetch(path, {
        credentials: "same-origin",
        ...opts,
        headers
    });

    let data = {};

    try {
        data = await res.json();
    } catch {
        // Некоторые ответы сервера могут быть не JSON.
    }

    if (!res.ok) {
        throw new Error(data.error || `Ошибка запроса (${res.status})`);
    }

    return data;
}

function showMessage(element, message, isError = false) {
    if (!element) return;

    element.textContent = message;
    element.classList.toggle("error", isError);
}

function showLogin(message = "") {
    me = null;

    appPanel?.classList.add("hidden");
    loginPanel?.classList.remove("hidden");

    if (loginMessage) {
        showMessage(loginMessage, message, Boolean(message));
    }
}

function showApp(user) {
    if (!user || user.role !== "owner") {
        showLogin("Доступ разрешён только владельцу магазина.");
        return;
    }

    me = user;

    loginPanel?.classList.add("hidden");
    appPanel?.classList.remove("hidden");

    // В этой версии используется только один аккаунт владельца.
    $("#usersPanel")?.classList.add("hidden");

    loadProducts();
}

function resetForm() {
    form.reset();

    form.elements.id.value = "";
    form.elements.visible.checked = true;
    form.elements.imagesText.value = "";

    $("#formTitle").textContent = "Добавить товар";
    $("#cancelEdit").classList.add("hidden");

    showMessage(productMessage, "");
    showMessage($("#uploadStatus"), "");
}

/* Вход */
$("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const loginForm = e.currentTarget;
    const f = new FormData(loginForm);

    showMessage(loginMessage, "Входим…");

    try {
        await api("/api/login", {
            method: "POST",
            body: JSON.stringify({
                username: f.get("username"),
                password: f.get("password")
            })
        });

        loginForm.reset();

        const user = await api("/api/me");
        showApp(user);
    } catch (err) {
        showMessage(loginMessage, err.message, true);
    }
});

/* Выход */
$("#logoutBtn").addEventListener("click", async () => {
    try {
        await api("/api/logout", {
            method: "POST",
            body: "{}"
        });
    } catch (err) {
        console.error("Ошибка выхода:", err);
    } finally {
        showLogin();
    }
});

/* Загрузка фотографий */
$("#imageFiles").addEventListener("change", async (e) => {
    const files = [...e.target.files];

    if (!files.length) return;

    const existing = form.elements.imagesText.value
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

    const uploaded = [];
    const status = $("#uploadStatus");

    showMessage(status, "Загружаем фото…");

    try {
        for (const file of files) {
            const fd = new FormData();
            fd.append("file", file);

            const res = await fetch("/api/upload", {
                method: "POST",
                body: fd,
                credentials: "same-origin"
            });

            let data = {};

            try {
                data = await res.json();
            } catch {}

            if (!res.ok) {
                throw new Error(
                    data.error || `Не удалось загрузить ${file.name}`
                );
            }

            if (!data.url) {
                throw new Error("Сервер не вернул адрес фотографии");
            }

            uploaded.push(data.url);
        }

        const allImages = [...new Set([...existing, ...uploaded])].slice(0, 8);

        form.elements.imagesText.value = allImages.join("\n");

        if (!form.elements.image.value.trim() && allImages.length) {
            form.elements.image.value = allImages[0];
        }

        showMessage(status, `Загружено фотографий: ${uploaded.length}`);
    } catch (err) {
        showMessage(status, err.message, true);
    } finally {
        // Позволяет повторно выбрать тот же файл.
        e.target.value = "";
    }
});

/* Загрузка товаров */
async function loadProducts() {
    if (loadingProducts) return;

    loadingProducts = true;

    const list = $("#products");
    list.textContent = "Загрузка…";

    try {
        if (!me) {
            throw new Error("Требуется вход");
        }

        const { products = [] } = await api("/api/products?all=1");

        list.replaceChildren();

        if (!products.length) {
            list.textContent = "Товаров пока нет.";
            return;
        }

        for (const p of products) {
            const card = document.createElement("article");
            card.className = "product";

            const img = document.createElement("img");
            img.src = p.image || "";
            img.alt = p.title || "Фото товара";
            img.loading = "lazy";

            const info = document.createElement("div");

            const title = document.createElement("h3");
            title.textContent = p.title;

            const details = document.createElement("p");
            details.textContent =
                `${Number(p.price).toLocaleString("ru-RU")} ₽ · ` +
                `Размеры: ${p.sizes} · ` +
                `${p.visible ? "Показывается" : "Скрыт"}`;

            const description = document.createElement("p");
            description.textContent = p.description;

            info.append(title, details, description);

            const actions = document.createElement("div");
            actions.className = "actions";

            const edit = document.createElement("button");
            edit.type = "button";
            edit.className = "ghost";
            edit.textContent = "Изменить";
            edit.addEventListener("click", () => editProduct(p));

            const visibility = document.createElement("button");
            visibility.type = "button";
            visibility.className = "ghost";
            visibility.textContent = p.visible ? "Скрыть" : "Показать";
            visibility.addEventListener("click", () => saveVisibility(p));

            const del = document.createElement("button");
            del.type = "button";
            del.className = "ghost";
            del.textContent = "Удалить";
            del.addEventListener("click", () => deleteProduct(p));

            actions.append(edit, visibility, del);
            card.append(img, info, actions);
            list.append(card);
        }
    } catch (err) {
        list.textContent = err.message;

        if (err.message === "Требуется вход") {
            showLogin();
        }
    } finally {
        loadingProducts = false;
    }
}

/* Редактирование товара */
function editProduct(p) {
    form.elements.id.value = p.id;
    form.elements.title.value = p.title;
    form.elements.price.value = p.price;
    form.elements.sizes.value = p.sizes;
    form.elements.description.value = p.description;
    form.elements.image.value = p.image;
    form.elements.visible.checked = Boolean(p.visible);

    form.elements.imagesText.value = (p.images || [p.image])
        .filter(Boolean)
        .join("\n");

    $("#formTitle").textContent = "Редактировать товар";
    $("#cancelEdit").classList.remove("hidden");

    showMessage(productMessage, "");

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}

/* Скрытие и повторная публикация */
async function saveVisibility(p) {
    try {
        await api(`/api/products/${encodeURIComponent(p.id)}`, {
            method: "PUT",
            body: JSON.stringify({
                ...p,
                visible: !p.visible
            })
        });

        showMessage(
            productMessage,
            p.visible ? "Товар скрыт." : "Товар опубликован."
        );

        await loadProducts();
    } catch (err) {
        showMessage(productMessage, err.message, true);
    }
}

/* Удаление товара */
async function deleteProduct(p) {
    if (!confirm(`Удалить «${p.title}»? Это действие нельзя отменить.`)) {
        return;
    }

    try {
        await api(`/api/products/${encodeURIComponent(p.id)}`, {
            method: "DELETE"
        });

        showMessage(productMessage, "Товар удалён.");
        await loadProducts();
    } catch (err) {
        showMessage(productMessage, err.message, true);
    }
}

/* Добавление и редактирование товара */
form.addEventListener("submit", async (e) => {
    e.preventDefault();

    showMessage(productMessage, "Сохраняем…");

    const f = new FormData(form);
    const id = String(f.get("id") || "").trim();

    const image = form.elements.image.value.trim();

    const extra = form.elements.imagesText.value
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

    const images = [...new Set([image, ...extra].filter(Boolean))].slice(0, 8);

    if (!image) {
        showMessage(productMessage, "Укажи главное фото товара.", true);
        return;
    }

    const payload = {
        title: String(f.get("title") || "").trim(),
        price: Number(f.get("price")),
        sizes: String(f.get("sizes") || "").trim(),
        description: String(f.get("description") || "").trim(),
        image,
        images,
        visible: f.get("visible") === "on"
    };

    try {
        await api(
            id
                ? `/api/products/${encodeURIComponent(id)}`
                : "/api/products",
            {
                method: id ? "PUT" : "POST",
                body: JSON.stringify(payload)
            }
        );

        resetForm();

        showMessage(productMessage, "Товар сохранён.");
        await loadProducts();
    } catch (err) {
        showMessage(productMessage, err.message, true);
    }
});

$("#cancelEdit").addEventListener("click", resetForm);

/* Проверка действующей сессии */
(async () => {
    try {
        const user = await api("/api/me");
        showApp(user);
    } catch {
        showLogin();
    }
})();
