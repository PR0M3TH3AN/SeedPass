document.addEventListener('DOMContentLoaded', () => {

    const navLinks = document.querySelectorAll('.docs-nav-list .doc-link');
    const contentArea = document.getElementById('docs-content');

    // Configure Marked.js (Optional but good practice)
    marked.setOptions({
        gfm: true,
        breaks: true,
        highlight: function (code, lang) {
            const language = hljs.getLanguage(lang) ? lang : 'plaintext';
            return hljs.highlight(code, { language }).value;
        }
    });

    async function fetchDocMarkdown(filename) {
        const candidateUrls = [
            `../docs/${filename}`,
            `./docs/${filename}`,
            `/docs/${filename}`,
            `https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/docs/${filename}`
        ];

        let lastError = null;
        for (const url of candidateUrls) {
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    throw new Error(`[${response.status}] Failed ${url}`);
                }

                const text = await response.text();
                const isLikelyHtmlDocument = /<!doctype html>|<html[\s>]/i.test(text);
                if (isLikelyHtmlDocument) {
                    throw new Error(`Received HTML instead of Markdown from ${url}`);
                }

                return text;
            } catch (error) {
                lastError = error;
            }
        }

        throw lastError || new Error(`Unable to load ${filename}`);
    }

    async function fetchAndRenderModule(filename) {
        // Show loading state
        contentArea.innerHTML = `
            <div class="loading-state">
                <i class="fas fa-circle-notch fa-spin"></i> Loading module ${filename}...
            </div>
        `;

        try {
            const markdownText = await fetchDocMarkdown(filename);

            // Parse Markdown to HTML
            const htmlContent = marked.parse(markdownText);

            // Render it in the content area with a wrapper for scoping styles
            contentArea.innerHTML = `<div class="markdown-body">${htmlContent}</div>`;

            // Additional styling logic if needed, like adding classes to elements
        } catch (error) {
            console.error(error);
            contentArea.innerHTML = `
                <div class="error-state">
                    <h3><i class="fas fa-exclamation-triangle"></i> SYSTEM ERROR</h3>
                    <p>${error.message || 'Unknown load error.'}</p>
                    <p>Failed to load module. Verify module path and server configuration.</p>
                </div>
            `;
        }
    }

    // Event listener for navigation links
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();

            // Update active state
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            const filename = link.getAttribute('data-file');
            fetchAndRenderModule(filename);

            // Update URL hash for simple state management (optional)
            window.location.hash = filename;
        });
    });

    // Handle initial load based on URL hash or default
    function initialLoad() {
        let initialFile = 'README.md'; // Default module

        if (window.location.hash) {
            // Get filename from hash (removing the # symbol)
            const hashFile = window.location.hash.substring(1);

            // Find corresponding link to make active
            const targetLink = document.querySelector(`.doc-link[data-file="${hashFile}"]`);
            if (targetLink) {
                navLinks.forEach(l => l.classList.remove('active'));
                targetLink.classList.add('active');
                initialFile = hashFile;
            }
        }

        fetchAndRenderModule(initialFile);
    }

    initialLoad();
});
