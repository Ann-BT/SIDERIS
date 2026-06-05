const BACKEND_URL = 'http://localhost:9001';
const ADMIN_EMAIL = 'admin@sideris.local';
const ADMIN_PASSWORD = 'siderisAdmin123!';

const PRODUCTS = [
  {
    title: "ZenBook Pro 15 OLED",
    description: "High-performance laptop with 15-inch OLED display, AMD Ryzen 9, 32GB RAM, and NVIDIA RTX graphics. Perfect for creators and professionals.",
    handle: "zenbook-pro-15-oled",
    status: "published",
    options: [
      { title: "Storage", values: ["512GB SSD", "1TB SSD"] }
    ],
    variants: [
      {
        title: "512GB SSD",
        sku: "ZEN-PRO-512",
        options: { "Storage": "512GB SSD" },
        prices: [{ amount: 1199, currency_code: "usd" }, { amount: 1199, currency_code: "eur" }]
      },
      {
        title: "1TB SSD",
        sku: "ZEN-PRO-1TB",
        options: { "Storage": "1TB SSD" },
        prices: [{ amount: 1399, currency_code: "usd" }, { amount: 1399, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "iPhone 15 Pro Max",
    description: "Titanium design, A17 Pro chip, customizable Action button, and the most powerful iPhone camera system ever.",
    handle: "iphone-15-pro-max",
    status: "published",
    options: [
      { title: "Color", values: ["Natural Titanium", "Blue Titanium"] }
    ],
    variants: [
      {
        title: "Natural Titanium",
        sku: "IPHONE-15-NAT",
        options: { "Color": "Natural Titanium" },
        prices: [{ amount: 1199, currency_code: "usd" }, { amount: 1199, currency_code: "eur" }]
      },
      {
        title: "Blue Titanium",
        sku: "IPHONE-15-BLUE",
        options: { "Color": "Blue Titanium" },
        prices: [{ amount: 1199, currency_code: "usd" }, { amount: 1199, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "Sony WH-1000XM5 Wireless",
    description: "Industry-leading noise-canceling wireless headphones with exceptional sound quality, smart features, and comfortable design.",
    handle: "sony-wh-1000xm5-wireless",
    status: "published",
    options: [
      { title: "Color", values: ["Black", "Silver"] }
    ],
    variants: [
      {
        title: "Black",
        sku: "SONY-XM5-BLK",
        options: { "Color": "Black" },
        prices: [{ amount: 399, currency_code: "usd" }, { amount: 399, currency_code: "eur" }]
      },
      {
        title: "Silver",
        sku: "SONY-XM5-SLV",
        options: { "Color": "Silver" },
        prices: [{ amount: 399, currency_code: "usd" }, { amount: 399, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "Mechanical Keyboard (MX Brown)",
    description: "Tactile mechanical gaming keyboard with aluminum frame, customizable RGB backlighting, and durable brown switches.",
    handle: "mechanical-keyboard-brown",
    status: "published",
    options: [
      { title: "Layout", values: ["US ANSI", "UK ISO"] }
    ],
    variants: [
      {
        title: "US ANSI",
        sku: "KEYBOARD-US",
        options: { "Layout": "US ANSI" },
        prices: [{ amount: 129, currency_code: "usd" }, { amount: 129, currency_code: "eur" }]
      },
      {
        title: "UK ISO",
        sku: "KEYBOARD-UK",
        options: { "Layout": "UK ISO" },
        prices: [{ amount: 129, currency_code: "usd" }, { amount: 129, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "Ergonomic Office Chair",
    description: "Premium mesh office chair with adjustable lumbar support, 3D armrests, and tilt lock mechanism for maximum comfort.",
    handle: "ergonomic-office-chair",
    status: "published",
    options: [
      { title: "Color", values: ["Classic Black", "Cool Gray"] }
    ],
    variants: [
      {
        title: "Classic Black",
        sku: "CHAIR-BLK",
        options: { "Color": "Classic Black" },
        prices: [{ amount: 299, currency_code: "usd" }, { amount: 299, currency_code: "eur" }]
      },
      {
        title: "Cool Gray",
        sku: "CHAIR-GRY",
        options: { "Color": "Cool Gray" },
        prices: [{ amount: 299, currency_code: "usd" }, { amount: 299, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "Smart Sports Watch",
    description: "GPS fitness smartwatch with heart rate monitoring, sleep analysis, and up to 14 days of battery life.",
    handle: "smart-sports-watch",
    status: "published",
    options: [
      { title: "Strap Size", values: ["40mm", "44mm"] }
    ],
    variants: [
      {
        title: "40mm",
        sku: "WATCH-40",
        options: { "Strap Size": "40mm" },
        prices: [{ amount: 249, currency_code: "usd" }, { amount: 249, currency_code: "eur" }]
      },
      {
        title: "44mm",
        sku: "WATCH-44",
        options: { "Strap Size": "44mm" },
        prices: [{ amount: 279, currency_code: "usd" }, { amount: 279, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "Leather Travel Backpack",
    description: "Handcrafted full-grain leather backpack with padded laptop compartment and weather-resistant zippers.",
    handle: "leather-travel-backpack",
    status: "published",
    options: [
      { title: "Material", values: ["Full Grain Leather"] }
    ],
    variants: [
      {
        title: "Full Grain Leather",
        sku: "BAG-LEATHER",
        options: { "Material": "Full Grain Leather" },
        prices: [{ amount: 189, currency_code: "usd" }, { amount: 189, currency_code: "eur" }]
      }
    ]
  },
  {
    title: "Smart Coffee Grinder",
    description: "Conical burr coffee grinder with 40 precise grind settings, built-in digital timer, and anti-static chamber.",
    handle: "smart-coffee-grinder",
    status: "published",
    options: [
      { title: "Voltage", values: ["110V", "220V"] }
    ],
    variants: [
      {
        title: "110V",
        sku: "GRINDER-110",
        options: { "Voltage": "110V" },
        prices: [{ amount: 149, currency_code: "usd" }, { amount: 149, currency_code: "eur" }]
      },
      {
        title: "220V",
        sku: "GRINDER-220",
        options: { "Voltage": "220V" },
        prices: [{ amount: 149, currency_code: "usd" }, { amount: 149, currency_code: "eur" }]
      }
    ]
  }
];

async function seed() {
  console.log("Authenticating as admin...");
  const authRes = await fetch(`${BACKEND_URL}/auth/user/emailpass`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD })
  });

  if (!authRes.ok) {
    throw new Error(`Auth failed with status ${authRes.status}`);
  }

  const { token } = await authRes.json();
  console.log("Authenticated successfully!");

  for (const product of PRODUCTS) {
    console.log(`Seeding product: ${product.title}...`);
    const res = await fetch(`${BACKEND_URL}/admin/products`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(product)
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`Failed to seed ${product.title}: status ${res.status}, error: ${errText}`);
    } else {
      console.log(`Successfully seeded ${product.title}`);
    }
  }
  console.log("Finished seeding all products!");
}

seed().catch(err => {
  console.error("Seeding error:", err);
});
