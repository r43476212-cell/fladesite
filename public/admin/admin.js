const $ = s => document.querySelector(s);

const loginPanel = $('#loginPanel');
const appPanel = $('#appPanel');
const loginMessage = $('#loginMessage');
const productMessage = $('#productMessage');
const form = $('#productForm');

let me = null;

async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };

    if (opts.body && typeof opts.body === 'string') {
        headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(path, {
        credentials: 'same-origin',
        ...opts,
        headers
    });

    let data = {};

    try {
        data = await res.json();
    } catch {}

    if (!res.ok) {
        throw new Error(data.error || 'Ошибка запроса');
    }

    return data;
}

function showApp(user) {
    me = user;

    loginPanel.classList.add('hidden');
    appPanel.classList.remove('hidden');

    $('#usersPanel').classList.toggle('hidden', user.role !== 'owner');

    loadProducts();

    if (user.role === 'owner') {
        loadUsers();
    }
}

function resetForm() {
    form.reset();
    form.elements.id.value = '';
    form.elements.visible.checked = true;
    form.elements.imagesText.value = '';

    $('#formTitle').textContent = 'Добавить товар';
    $('#cancelEdit').classList.add('hidden');
    $('#productMessage').textContent = '';
    $('#uploadStatus').textContent = '';
}

/* Вход в панель */
$('#loginForm').addEventListener('submit', async e => {
    e.preventDefault();

    // Сохраняем ссылку на форму до await
    const loginForm = e.currentTarget;

    loginMessage.textContent = 'Входим…';

    const f = new FormData(loginForm);

    try {
        await api('/api/login', {
            method: 'POST',
            body: JSON.stringify({
                username: f.get('username'),
                password: f.get('password')
            })
        });

        loginForm.reset();

        const user = await api('/api/me');
        showApp(user);
    } catch (err) {
        loginMessage.textContent = err.message;
    }
});

/* Выход */
$('#logoutBtn').addEventListener('click', async () => {
    try {
        await api('/api/logout', {
            method: 'POST',
            body: '{}'
        });
    } catch (err) {
        console.error('Ошибка выхода:', err);
    } finally {
        appPanel.classList.add('hidden');
        loginPanel.classList.remove('hidden');
        me = null;
    }
});

/* Загрузка фотографий */
$('#imageFiles').addEventListener('change', async e => {
    const files = [...e.target.files];

    if (!files.length) return;

    const uploaded = [];

    $('#uploadStatus').textContent = 'Загружаем фото…';

    try {
        for (const file of files) {
            const fd = new FormData();
            fd.append('file', file);

            const r = await fetch('/api/upload', {
                method: 'POST',
                body: fd,
                credentials: 'same-origin'
            });

            const d = await r.json();

            if (!r.ok) {
                throw new Error(d.error || 'Не удалось загрузить фото');
            }

            uploaded.push(d.url);
        }

        const existing = form.elements.imagesText.value.trim();

        form.elements.imagesText.value = [
            existing,
            ...uploaded
        ].filter(Boolean).join('\n');

        if (!form.elements.image.value && uploaded.length) {
            form.elements.image.value = uploaded[0];
        }

        $('#uploadStatus').textContent =
            `Загружено фотографий: ${uploaded.length}`;
    } catch (err) {
        $('#uploadStatus').textContent = err.message;
    }
});

/* Загрузка товаров */
async function loadProducts() {
    const list = $('#products');
    list.textContent = 'Загрузка…';

    try {
        const { products } = await api('/api/products?all=1');

        list.replaceChildren();

        if (!products.length) {
            list.textContent = 'Товаров пока нет.';
            return;
        }

        for (const p of products) {
            const card = document.createElement('article');
            card.className = 'product';

            const img = document.createElement('img');
            img.src = p.image;
            img.alt = '';

            const info = document.createElement('div');

            const title = document.createElement('h3');
            title.textContent = p.title;

            const details = document.createElement('p');
            details.textContent =
                `${Number(p.price).toLocaleString('ru-RU')} ₽ · ` +
                `Размеры: ${p.sizes} · ` +
                `${p.visible ? 'Показывается' : 'Скрыт'}`;

            const desc = document.createElement('p');
            desc.textContent = p.description;

            info.append(title, details, desc);

            const actions = document.createElement('div');
            actions.className = 'actions';

            const edit = document.createElement('button');
            edit.className = 'ghost';
            edit.textContent = 'Изменить';
            edit.onclick = () => editProduct(p);

            const visibility = document.createElement('button');
            visibility.className = 'ghost';
            visibility.textContent = p.visible ? 'Скрыть' : 'Показать';
            visibility.onclick = () => saveVisibility(p);

            const del = document.createElement('button');
            del.className = 'ghost';
            del.textContent = 'Удалить';
            del.onclick = () => deleteProduct(p);

            actions.append(edit, visibility, del);
            card.append(img, info, actions);
            list.append(card);
        }
    } catch (err) {
        list.textContent = err.message;

        if (err.message === 'Требуется вход') {
            appPanel.classList.add('hidden');
            loginPanel.classList.remove('hidden');
        }
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
    form.elements.visible.checked = !!p.visible;
    form.elements.imagesText.value = (p.images || []).join('\n');

    $('#formTitle').textContent = 'Редактировать товар';
    $('#cancelEdit').classList.remove('hidden');

    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

/* Изменение видимости товара */
async function saveVisibility(p) {
    try {
        await api('/api/products/' + p.id, {
            method: 'PUT',
            body: JSON.stringify({
                ...p,
                visible: !p.visible
            })
        });

        loadProducts();
    } catch (e) {
        productMessage.textContent = e.message;
    }
}

/* Удаление товара */
async function deleteProduct(p) {
    if (!confirm(`Удалить «${p.title}»?`)) return;

    try {
        await api('/api/products/' + p.id, {
            method: 'DELETE'
        });

        loadProducts();
    } catch (e) {
        productMessage.textContent = e.message;
    }
}

/* Сохранение товара */
form.addEventListener('submit', async e => {
    e.preventDefault();

    productMessage.textContent = 'Сохраняем…';

    const f = new FormData(form);
    const id = f.get('id');

    const image = form.elements.image.value.trim();

    const extra = form.elements.imagesText.value
        .split(/\n/)
        .map(s => s.trim())
        .filter(Boolean);

    const payload = {
        title: f.get('title').trim(),
        price: Number(f.get('price')),
        sizes: f.get('sizes').trim(),
        description: f.get('description').trim(),
        image,
        images: [...new Set([image, ...extra])],
        visible: f.get('visible') === 'on'
    };

    try {
        await api(
            id ? '/api/products/' + id : '/api/products',
            {
                method: id ? 'PUT' : 'POST',
                body: JSON.stringify(payload)
            }
        );

        resetForm();
        productMessage.textContent = 'Сохранено';

        loadProducts();
    } catch (err) {
        productMessage.textContent = err.message;
    }
});

$('#cancelEdit').addEventListener('click', resetForm);

/* Создание аккаунта */
$('#userForm').addEventListener('submit', async e => {
    e.preventDefault();

    // Исправление: сохраняем ссылку до await
    const userForm = e.currentTarget;

    const f = new FormData(userForm);

    $('#userMessage').textContent = 'Создаём аккаунт…';

    try {
        await api('/api/users', {
            method: 'POST',
            body: JSON.stringify({
                username: f.get('username'),
                password: f.get('password'),
                role: f.get('role')
            })
        });

        userForm.reset();

        $('#userMessage').textContent = 'Аккаунт создан';

        loadUsers();
    } catch (err) {
        $('#userMessage').textContent = err.message;
    }
});

/* Список аккаунтов */
async function loadUsers() {
    const list = $('#usersList');

    try {
        const { users } = await api('/api/users');

        list.replaceChildren();

        for (const u of users) {
            const row = document.createElement('article');
            row.className = 'product';

            const info = document.createElement('div');

            const title = document.createElement('h3');
            title.textContent = u.username;

            const role = document.createElement('p');
            role.textContent =
                u.role === 'owner'
                    ? 'Владелец'
                    : 'Сотрудник магазина';

            info.append(title, role);

            const actions = document.createElement('div');
            actions.className = 'actions';

            if (u.id !== me?.sub && u.role !== 'owner') {
                const del = document.createElement('button');

                del.className = 'ghost';
                del.textContent = 'Удалить аккаунт';

                del.onclick = async () => {
                    if (!confirm(`Удалить аккаунт ${u.username}?`)) {
                        return;
                    }

                    try {
                        await api('/api/users/' + u.id, {
                            method: 'DELETE'
                        });

                        loadUsers();
                    } catch (err) {
                        $('#userMessage').textContent = err.message;
                    }
                };

                actions.append(del);
            }

            row.append(info, actions);
            list.append(row);
        }
    } catch (e) {
        list.textContent = e.message;
    }
}

/* Проверка существующей сессии */
api('/api/me')
    .then(showApp)
    .catch(() => {
        // Если пользователь не авторизован,
        // остаёмся на экране входа.
    });