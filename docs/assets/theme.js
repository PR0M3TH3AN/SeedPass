document.addEventListener('DOMContentLoaded', () => {
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const themeToggle = document.getElementById('theme-toggle');
  const searchInput = document.getElementById('search-input');
  const searchResults = document.getElementById('search-results');
  const sidebar = document.getElementById('sidebar');
  const sidebarOverlay = document.getElementById('sidebar-overlay');
  const root = document.documentElement;

  function setTheme(theme) {
    root.dataset.theme = theme;
    localStorage.setItem('theme', theme);
  }
  const stored = localStorage.getItem('theme');
  if (stored) setTheme(stored);

  if (window.innerWidth > 768) {
    document.body.classList.add('sidebar-open');
  }

  sidebarToggle?.addEventListener('click', () => {
    document.body.classList.toggle('sidebar-open');
  });

  sidebarOverlay?.addEventListener('click', () => {
    document.body.classList.remove('sidebar-open');
  });

  themeToggle?.addEventListener('click', () => {
    const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
  });

  // search
  let lunrIndex;
  let docs = [];
  async function loadIndex() {
    if (lunrIndex) return;
    try {
      const res = await fetch('/search-index.json');
      const data = await res.json();
      lunrIndex = lunr.Index.load(data.index);
      docs = data.docs;
    } catch (e) {
      console.error('Search index failed to load', e);
    }
  }

  function highlight(text, q) {
    const re = new RegExp('(' + q.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&') + ')', 'gi');
    return text.replace(re, '<mark>$1</mark>');
  }

  searchInput?.addEventListener('input', async e => {
    const q = e.target.value.trim();
    await loadIndex();
    if (!lunrIndex || !q) {
      searchResults.style.display = 'none';
      searchResults.innerHTML = '';
      return;
    }
    const matches = lunrIndex.search(q);
    searchResults.innerHTML = '';
    if (!matches.length) {
      searchResults.innerHTML = '<div class="no-results">No matches found</div>';
      searchResults.style.display = 'block';
      return;
    }
    matches.forEach(m => {
      const doc = docs.find(d => d.id === m.ref);
      if (!doc) return;
      const a = document.createElement('a');
      a.href = doc.url;
      const snippet = doc.body ? doc.body.slice(0, 160) + (doc.body.length > 160 ? '...' : '') : '';
      a.innerHTML = '<strong>' + highlight(doc.title, q) + '</strong><br><small>' + highlight(snippet, q) + '</small>';
      searchResults.appendChild(a);
    });
    searchResults.style.display = 'block';
  });

  document.addEventListener('click', e => {
    if (!searchResults.contains(e.target) && e.target !== searchInput) {
      searchResults.style.display = 'none';
    }
    if (
      window.innerWidth <= 768 &&
      document.body.classList.contains('sidebar-open') &&
      sidebar &&
      !sidebar.contains(e.target) &&
      e.target !== sidebarToggle
    ) {
      document.body.classList.remove('sidebar-open');
    }
  });

  // breadcrumbs
  const bc = document.getElementById('breadcrumbs');
  if (bc) {
    const parts = location.pathname.split('/').filter(Boolean);
    let path = '';
    bc.innerHTML = '<a href="/">Home</a>';
    parts.forEach((p) => {
      path += '/' + p;
      bc.innerHTML += ' / <a href="' + path + '">' + p.replace(/-/g, ' ') + '</a>';
    });
  }
});
