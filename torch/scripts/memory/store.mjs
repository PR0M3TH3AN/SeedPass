console.log("Mock memory store");
import fs from 'fs';
fs.mkdirSync(".scheduler-memory/latest/daily/", { recursive: true });
fs.writeFileSync(".scheduler-memory/latest/daily/store.ok", "MEMORY_STORED");
