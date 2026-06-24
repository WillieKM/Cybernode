// js/blog.js
// Fetches and parses markdown posts from /_posts/
// Uses marked.js for markdown rendering (loaded via CDN in blog pages)
// ----------------------------------------------------------------

const POSTS_INDEX = '/_posts/index.json'; // generated at build, see below

// ── ESCAPE UNTRUSTED STRINGS BEFORE INTERPOLATING INTO HTML ──────
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── PARSE FRONTMATTER ────────────────────────────────────────────
function parseFrontmatter(raw) {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!match) return { meta: {}, body: raw };

  const meta = {};
  match[1].split('\n').forEach(line => {
    const [key, ...val] = line.split(':');
    if (key && val.length) meta[key.trim()] = val.join(':').trim().replace(/^"|"$/g, '');
  });

  return { meta, body: match[2] };
}

// ── FORMAT DATE ──────────────────────────────────────────────────
function formatDate(dateStr) {
  try {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric'
    });
  } catch { return dateStr; }
}

// ── CATEGORY BADGE COLOR ─────────────────────────────────────────
function categoryColor(cat) {
  const map = {
    'Threat Intel':      '#ff4466',
    'CVE Alerts':        '#ffaa22',
    'Compliance':        '#00d4ff',
    'How-To':            '#00dd88',
    'Platform Updates':  '#aa88ff',
  };
  return map[cat] || '#00d4ff';
}

// ── LOAD ALL POSTS (for blog index) ─────────────────────────────
async function loadPostList() {
  // We fetch a manifest of post filenames generated at build time
  // Fallback: fetch individual known posts
  try {
    const res = await fetch(POSTS_INDEX);
    if (res.ok) {
      const files = await res.json();
      return Promise.all(files.map(loadPostMeta));
    }
  } catch {}

  // Static fallback list — update this manually when you add posts
  const fallback = [
    '/posts/2026-04-12-welcome-to-cyber-node-blog.md',
    '/posts/2026-04-10-cve-2026-1842-critical-exploit.md',
  ];
  return Promise.all(fallback.map(loadPostMeta));
}

async function loadPostMeta(path) {
  try {
    const res = await fetch(path);
    if (!res.ok) return null;
    const raw = await res.text();
    const { meta } = parseFrontmatter(raw);
    return { ...meta, path, slug: path.split('/').pop().replace('.md', '') };
  } catch { return null; }
}

// ── RENDER BLOG INDEX ────────────────────────────────────────────
async function renderBlogIndex(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = '<p style="font-family:\'Share Tech Mono\',monospace;color:#90bcd8;text-align:center;padding:40px;">// LOADING POSTS...</p>';

  const posts = (await loadPostList()).filter(Boolean);

  if (!posts.length) {
    container.innerHTML = '<p style="font-family:\'Share Tech Mono\',monospace;color:#90bcd8;text-align:center;padding:40px;">// NO POSTS FOUND</p>';
    return;
  }

  // Sort newest first
  posts.sort((a, b) => new Date(b.date) - new Date(a.date));

  container.innerHTML = posts.map(post => `
    <article class="blog-card">
      <div class="blog-card-meta">
        <span class="blog-category" style="border-color:${categoryColor(post.category)};color:${categoryColor(post.category)}">
          ${escapeHtml(post.category || 'General')}
        </span>
        <span class="blog-date">${escapeHtml(formatDate(post.date))}</span>
      </div>
      <h2 class="blog-card-title">
        <a href="/blog/post.html?slug=${encodeURIComponent(post.slug)}">${escapeHtml(post.title)}</a>
      </h2>
      <p class="blog-card-desc">${escapeHtml(post.description || '')}</p>
      <div class="blog-card-footer">
        <span class="blog-author">// ${escapeHtml(post.author || 'Cyber-Node Team')}</span>
        <a href="/blog/post.html?slug=${encodeURIComponent(post.slug)}" class="blog-read-more">READ_MORE →</a>
      </div>
    </article>
  `).join('');
}

// ── RENDER SINGLE POST ───────────────────────────────────────────
async function renderPost(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const params = new URLSearchParams(window.location.search);
  const slug   = params.get('slug');

  if (!slug) {
    container.innerHTML = '<p style="color:#ff4466;font-family:monospace;text-align:center;padding:60px;">// POST NOT FOUND</p>';
    return;
  }

  container.innerHTML = '<p style="font-family:\'Share Tech Mono\',monospace;color:#90bcd8;text-align:center;padding:60px;">// DECRYPTING POST...</p>';

  try {
    const res = await fetch(`/_posts/${slug}.md`);
    if (!res.ok) throw new Error('Not found');

    const raw = await res.text();
    const { meta, body } = parseFrontmatter(raw);

    // Update page title and meta
    document.title = `${meta.title} | Cyber-Node`;
    const descMeta = document.querySelector('meta[name="description"]');
    if (descMeta && meta.description) descMeta.setAttribute('content', meta.description);

    const catColor = categoryColor(meta.category);
    const rawHtml = typeof marked !== 'undefined' ? marked.parse(body) : escapeHtml(body).replace(/\n/g, '<br>');
    // Markdown bodies come from blog posts written through the CMS, but marked
    // passes through raw inline HTML by default — sanitize before it ever hits innerHTML.
    const html = typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(rawHtml) : escapeHtml(rawHtml);

    container.innerHTML = `
      <div class="post-header">
        <div class="post-meta-top">
          <span class="blog-category" style="border-color:${catColor};color:${catColor}">${escapeHtml(meta.category || 'General')}</span>
          <span class="blog-date">${escapeHtml(formatDate(meta.date))}</span>
        </div>
        <h1 class="post-title">${escapeHtml(meta.title)}</h1>
        <p class="post-description">${escapeHtml(meta.description || '')}</p>
        <div class="post-author">// Written by <strong>${escapeHtml(meta.author || 'Cyber-Node Team')}</strong></div>
      </div>
      ${meta.cover ? `<img src="${escapeHtml(meta.cover)}" alt="${escapeHtml(meta.title)}" class="post-cover">` : ''}
      <div class="post-body">${html}</div>
      <div class="post-footer">
        <a href="/blog/" class="cn-btn btn-outline">← Back to Blog</a>
      </div>
    `;
  } catch {
    container.innerHTML = `
      <div style="text-align:center;padding:80px 20px;">
        <p style="font-family:'Share Tech Mono',monospace;color:#ff4466;font-size:14px;margin-bottom:20px;">// POST NOT FOUND</p>
        <a href="/blog/" style="color:#00d4ff;font-family:'Share Tech Mono',monospace;">← Return to Blog</a>
      </div>
    `;
  }
}

// Export for use in HTML pages
window.CyberBlog = { renderBlogIndex, renderPost };
