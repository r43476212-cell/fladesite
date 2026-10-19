PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 password_salt TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin' CHECK(role IN ('owner','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id TEXT PRIMARY KEY,
 title TEXT NOT NULL,
 price INTEGER NOT NULL CHECK(price >= 0),
 sizes TEXT NOT NULL,
 description TEXT NOT NULL,
 image TEXT NOT NULL,
 images TEXT NOT NULL DEFAULT '[]',
 visible INTEGER NOT NULL DEFAULT 1 CHECK(visible IN (0,1)),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO products (id,title,price,sizes,description,image,images,visible) VALUES
('adidas-marathon-tr-26','Кроссовки adidas Marathon TR 26',1899,'41, 42, 43, 44, 45','Светло-серые кроссовки с чёрными акцентами, шнуровкой и рельефной подошвой. Текстурированный верх и лаконичный дизайн подойдут для повседневных городских образов.','assets/marathon-tr-26-1.jpg','["assets/marathon-tr-26-1.jpg","assets/marathon-tr-26-2.jpg"]',1);

CREATE TABLE IF NOT EXISTS product_images (
  id TEXT PRIMARY KEY,
  mime_type TEXT NOT NULL CHECK (
    mime_type IN ('image/jpeg', 'image/png', 'image/webp')
  ),
  image_data TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
