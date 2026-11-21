/**
 * DevTools bootstrap. Runs in the hidden devtools_page context, whose only job
 * is to register the panel. The React application lives in panel.html.
 */
chrome.devtools.panels.create(
  'NetXRay',
  '', // Chrome falls back to a default extension icon
  'panel.html',
);
