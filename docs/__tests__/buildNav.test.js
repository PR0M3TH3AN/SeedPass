const { buildNav } = require('../src/generator');

test('generates navigation tree', () => {
  const pages = [
    { file: 'guide/install.md', data: { title: 'Install', order: 1 } },
    { file: 'guide/usage.md', data: { title: 'Usage', order: 2 } },
    { file: 'guide/nested/info.md', data: { title: 'Info', order: 1 } }
  ];
  const tree = buildNav(pages);
  const guide = tree.find(n => n.name === 'guide');
  expect(guide).toBeDefined();
  expect(guide.children.length).toBe(3);
  const install = guide.children.find(c => c.name === 'install.md');
  expect(install.path).toBe('/guide/install.html');
});

test('adds display names and section flags', () => {
  const pages = [
    { file: '02-api.md', data: { title: 'API', order: 2 } },
    { file: '01-guide/index.md', data: { title: 'Guide', order: 1 } },
    { file: '01-guide/setup.md', data: { title: 'Setup', order: 2 } },
    { file: 'index.md', data: { title: 'Home', order: 10 } }
  ];
  const nav = buildNav(pages);
  expect(nav[0].name).toBe('index.md');
  const guide = nav.find(n => n.name === '01-guide');
  expect(guide.displayName).toBe('Guide');
  expect(guide.isSection).toBe(true);
  const api = nav.find(n => n.name === '02-api.md');
  expect(api.displayName).toBe('API');
  // alphabetical within same order
  expect(nav[1].name).toBe('01-guide');
  expect(nav[2].name).toBe('02-api.md');
});
