function injectStyles() {
    const styleId = 'pwn-dynamic-styles';
    if (!document.getElementById(styleId)) {
        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = `
            /* Target the token specifically */
            span.param-token {
                color: rgb(0, 255, 30) !important; /* Bright Green */
                font-weight: bold;
                display: inline-block;
                text-shadow: 0 0 2px rgba(46, 204, 113, 0.2);
                line-height: 1.2;
                padding: 0 2px;
                vertical-align: baseline;
            }
            
            /* Ensure it overrides code block syntax highlighting */
            .code-block code span.param-token,
            pre code span.param-token {
                color: rgb(0, 255, 30) !important;
            }
        `;
        document.head.appendChild(style);
    }
}

function setupMarkedOptions() {
    const renderer = new marked.Renderer();
    const originalLinkRenderer = renderer.link;
    
    renderer.link = function(href, title, text) {
        const html = originalLinkRenderer.call(this, href, title, text);
        const isExternal = /^https?:\/\//i.test(href);
        if (!isExternal) {
            return html;
        }
        return html.replace(/^<a /, '<a target="_blank" rel="noopener noreferrer" ');
    };
    
    marked.setOptions({
        renderer: renderer,
        breaks: true,
        gfm: true
    });
}
