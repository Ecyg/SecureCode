<?php
$snippets = require 'snippets.php';
$currentId = isset($_GET['id']) ? (int)$_GET['id'] : $snippets[0]['id'];

// Find current snippet
$currentSnippet = null;
foreach ($snippets as $snippet) {
    if ($snippet['id'] === $currentId) {
        $currentSnippet = $snippet;
        break;
    }
}
if (!$currentSnippet) {
    $currentSnippet = $snippets[0];
}

// Group snippets strictly by language (extract from title)
function get_language($title) {
    if (preg_match('/\\(([^)]+)\\)/', $title, $matches)) {
        return $matches[1];
    }
    return 'Other';
}

$langGroups = [];
foreach ($snippets as $snippet) {
    $lang = get_language($snippet['title']);
    if (!isset($langGroups[$lang])) {
        $langGroups[$lang] = [];
    }
    $langGroups[$lang][] = $snippet;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Vulnerable Code Review</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="app-container">
    <aside class="sidebar" id="sidebar">
        <button id="sidebar-toggle" aria-label="Collapse sidebar">&#9776;</button>
        <h2>Snippets</h2>
        <div id="language-list">
            <?php foreach ($langGroups as $lang => $snippetsInLang): ?>
                <div class="lang-section">
                    <div class="lang-header" data-lang="<?= htmlspecialchars($lang) ?>">
                        <?= htmlspecialchars($lang) ?>
                        <span class="dropdown-arrow">&#9660;</span>
                    </div>
                    <ul class="snippet-list" data-lang="<?= htmlspecialchars($lang) ?>">
                        <?php foreach ($snippetsInLang as $snippet): ?>
                            <li class="snippet-item<?php if ($snippet['id'] === $currentSnippet['id']) echo ' active'; ?>" data-id="<?= $snippet['id'] ?>">
                                <?= htmlspecialchars(preg_replace('/ \([^)]*\)/', '', $snippet['title'])) ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endforeach; ?>
        </div>
    </aside>
    <main class="main-content" id="main-content">
        <h1><?= htmlspecialchars($currentSnippet['title']) ?></h1>
        <pre class="code-block"><code><?= htmlspecialchars($currentSnippet['code']) ?></code></pre>
        <div class="dropdown">
            <button id="dropdown-btn">Vulnerability Details ▼</button>
            <div class="dropdown-content" id="dropdown-content">
                <strong><?= htmlspecialchars($currentSnippet['vulnerability']) ?></strong>
                <p><?= htmlspecialchars($currentSnippet['summary']) ?></p>
                <ul>
                    <?php foreach ($currentSnippet['resources'] as $url): ?>
                        <li><a href="<?= htmlspecialchars($url) ?>" target="_blank">Learn more</a></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
        <button id="next-btn">Next Snippet</button>
    </main>
</div>
<script src="assets/script.js"></script>
<script>
window.snippets = <?= json_encode($snippets) ?>;
window.currentId = <?= $currentSnippet['id'] ?>;
</script>
</body>
</html>
