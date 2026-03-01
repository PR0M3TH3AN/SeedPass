console.log("Mock memory retrieve");
import fs from 'fs';
fs.mkdirSync(".scheduler-memory/latest/daily/", { recursive: true });
fs.writeFileSync(".scheduler-memory/latest/daily/retrieve.ok", "MEMORY_RETRIEVED");
