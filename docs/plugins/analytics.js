module.exports = {
  onPageRendered: async ({ html, file }) => {
    // Example: inject analytics script into each page
    const snippet = '\n<script>console.log("Page viewed: ' + file + '")</script>';
    return { html: html.replace('</body>', `${snippet}</body>`) };
  }
};
