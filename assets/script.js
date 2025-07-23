document.addEventListener('DOMContentLoaded', function() {
    const snippets = window.snippets;
    let currentId = window.currentId;

    const snippetList = document.getElementById('snippet-list');
    const mainContent = document.querySelector('.main-content');
    const dropdownBtn = document.getElementById('dropdown-btn');
    const dropdownContent = document.getElementById('dropdown-content');
    const nextBtn = document.getElementById('next-btn');

    function renderSnippet(snippet) {
        mainContent.querySelector('h1').textContent = snippet.title;
        mainContent.querySelector('.code-block code').textContent = snippet.code;
        dropdownContent.innerHTML = `
            <strong>${snippet.vulnerability}</strong>
            <p>${snippet.summary}</p>
            <ul>
                ${snippet.resources.map(url => `<li><a href="${url}" target="_blank">Learn more</a></li>`).join('')}
            </ul>
        `;
        // Highlight active in sidebar
        Array.from(snippetList.children).forEach(li => {
            li.classList.toggle('active', parseInt(li.dataset.id) === snippet.id);
        });
        currentId = snippet.id;
    }

    snippetList.addEventListener('click', function(e) {
        if (e.target.classList.contains('snippet-item')) {
            const id = parseInt(e.target.dataset.id);
            const snippet = snippets.find(s => s.id === id);
            if (snippet) {
                renderSnippet(snippet);
            }
        }
    });

    nextBtn.addEventListener('click', function() {
        let idx = snippets.findIndex(s => s.id === currentId);
        idx = (idx + 1) % snippets.length;
        renderSnippet(snippets[idx]);
    });

    dropdownBtn.addEventListener('click', function() {
        dropdownContent.style.display = dropdownContent.style.display === 'block' ? 'none' : 'block';
    });

    // Hide dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (!dropdownBtn.contains(e.target) && !dropdownContent.contains(e.target)) {
            dropdownContent.style.display = 'none';
        }
    });
});
